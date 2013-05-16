#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef __linux__
#include <alloca.h>
#endif
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <libxml/tree.h>
#include "cloudfsapi.h"
#include "config.h"

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"

#define REQUEST_RETRIES 4

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
static CURL *curl_pool[1024];
static int curl_pool_count = 0;
static int debug = 0;
static int verify_ssl = 1;
static int rhel5_mode = 0;

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
static pthread_mutex_t *ssl_lockarray;
static void lock_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&(ssl_lockarray[type]));
  else
    pthread_mutex_unlock(&(ssl_lockarray[type]));
}

static unsigned long thread_id()
{
  return (unsigned long)pthread_self();
}
#endif

static void rewrite_url_snet(char *url)
{
  char protocol[MAX_URL_SIZE];
  char rest[MAX_URL_SIZE];
  sscanf(url, "%[a-z]://%s", protocol, rest);
  if (strncasecmp(rest, "snet-", 5))
    sprintf(url, "%s://snet-%s", protocol, rest);
}

static size_t xml_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  xmlParseChunk((xmlParserCtxtPtr)stream, (char *)ptr, size * nmemb, 0);
  return size * nmemb;
}

static CURL *get_connection(const char *path)
{
  pthread_mutex_lock(&pool_mut);
  CURL *curl = curl_pool_count ? curl_pool[--curl_pool_count] : curl_easy_init();
  if (!curl)
  {
    debugf("curl alloc failed");
    abort();
  }
  pthread_mutex_unlock(&pool_mut);
  return curl;
}

static void return_connection(CURL *curl)
{
  pthread_mutex_lock(&pool_mut);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&pool_mut);
}

static void add_header(curl_slist **headers, const char *name, const char *value)
{
  char x_header[MAX_HEADER_SIZE];
  snprintf(x_header, sizeof(x_header), "%s: %s", name, value);
  *headers = curl_slist_append(*headers, x_header);
}

static int send_request(char *method, const char *path, FILE *fp, xmlParserCtxtPtr xmlctx, curl_slist *extra_headers)
{
  char url[MAX_URL_SIZE];
  char *slash;
  long response = -1;
  int tries = 0;

  if (!storage_url[0])
  {
    debugf("send_request with no storage_url?");
    abort();
  }

  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
  {
    *slash = '/';
    memmove(slash+1, slash+3, strlen(slash+3)+1);
  }
  while (*path == '/')
    path++;
  snprintf(url, sizeof(url), "%s/%s", storage_url, path);

  // retry on failures
  for (tries = 0; tries < REQUEST_RETRIES; tries++)
  {
    CURL *curl = get_connection(path);
    if (rhel5_mode)
      curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
    curl_slist *headers = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
    add_header(&headers, "X-Auth-Token", storage_token);
    if (!strcasecmp(method, "MKDIR"))
    {
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
      add_header(&headers, "Content-Type", "application/directory");
    }
    else if (!strcasecmp(method, "PUT") && fp)
    {
      rewind(fp);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, cloudfs_file_size(fileno(fp)));
      curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    }
    else if (!strcasecmp(method, "GET"))
    {
      if (fp)
      {
        rewind(fp); // make sure the file is ready for a-writin'
        fflush(fp);
        if (ftruncate(fileno(fp), 0) < 0)
        {
          debugf("ftruncate failed.  I don't know what to do about that.");
          abort();
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
      }
      else if (xmlctx)
      {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
      }
    }
    else
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    /* add the headers from extra_headers if any */
    curl_slist *extra;
    for (extra = extra_headers; extra; extra = extra->next)
    {
      debugf("adding header: %s", extra->data);
      headers = curl_slist_append(headers, extra->data);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return_connection(curl);
    if (response >= 200 && response < 400)
      return response;
    sleep(8 << tries); // backoff
    if (response == 401 && !cloudfs_connect()) // re-authenticate on 401s
      return response;
    if (xmlctx)
      xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);
  }
  return response;
}

static size_t header_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  char *header = (char *)alloca(size * nmemb + 1);
  char *head = (char *)alloca(size * nmemb + 1);
  char *value = (char *)alloca(size * nmemb + 1);
  memcpy(header, (char *)ptr, size * nmemb);
  header[size * nmemb] = '\0';
  if (sscanf(header, "%[^:]: %[^\r\n]", head, value) == 2)
  {
    if (!strncasecmp(head, "x-auth-token", size * nmemb))
      strncpy(storage_token, value, sizeof(storage_token));
    if (!strncasecmp(head, "x-storage-url", size * nmemb))
      strncpy(storage_url, value, sizeof(storage_url));
  }
  return size * nmemb;
}

/*
 * Public interface
 */

void cloudfs_init()
{
  LIBXML_TEST_VERSION
  curl_global_init(CURL_GLOBAL_ALL);
  pthread_mutex_init(&pool_mut, NULL);
  curl_version_info_data *cvid = curl_version_info(CURLVERSION_NOW);

  // CentOS/RHEL 5 get stupid mode, because they have a broken libcurl
  if (cvid->version_num == RHEL5_LIBCURL_VERSION)
  {
    debugf("RHEL5 mode enabled.");
    rhel5_mode = 1;
  }

  if (!strncasecmp(cvid->ssl_version, "openssl", 7))
  {
    #ifdef HAVE_OPENSSL
    int i;
    ssl_lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                              sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_init(&(ssl_lockarray[i]), NULL);
    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)())lock_callback);
    #endif
  }
  else if (!strncasecmp(cvid->ssl_version, "nss", 3))
  {
    // allow https to continue working after forking (for RHEL/CentOS 6)
    setenv("NSS_STRICT_NOFORK", "DISABLED", 1);
  }
}

int cloudfs_object_read_fp(const char *path, FILE *fp)
{
  fflush(fp);
  rewind(fp);
  char *encoded = curl_escape(path, 0);
  int response = send_request("PUT", encoded, fp, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_object_write_fp(const char *path, FILE *fp)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("GET", encoded, fp, NULL, NULL);
  curl_free(encoded);
  fflush(fp);
  if ((response >= 200 && response < 300) || ftruncate(fileno(fp), 0))
    return 1;
  rewind(fp);
  return 0;
}

int cloudfs_object_truncate(const char *path, off_t size)
{
  char *encoded = curl_escape(path, 0);
  int response;
  if (size == 0)
  {
    FILE *fp = fopen("/dev/null", "r");
    response = send_request("PUT", encoded, fp, NULL, NULL);
    fclose(fp);
  }
  else
  {//TODO: this is busted
    response = send_request("GET", encoded, NULL, NULL, NULL);
  }
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_list_directory(const char *path, dir_entry **dir_list)
{
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  char last_subdir[MAX_PATH_SIZE] = "";
  int prefix_length = 0;
  int response = 0;
  int retval = 0;
  int entry_count = 0;

  *dir_list = NULL;
  xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
  xmlParserCtxtPtr xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  if (!strcmp(path, "") || !strcmp(path, "/"))
  {
    path = "";
    strncpy(container, "/?format=xml", sizeof(container));
  }
  else
  {
    sscanf(path, "/%[^/]/%[^\n]", container, object);
    char *encoded_container = curl_escape(container, 0);
    char *encoded_object = curl_escape(object, 0);

    // The empty path doesn't get a trailing slash, everything else does
    char *trailing_slash;
    prefix_length = strlen(object);
    if (object[0] == 0)
      trailing_slash = "";
    else
    {
      trailing_slash = "/";
      prefix_length++;
    }

    snprintf(container, sizeof(container), "%s?format=xml&delimiter=/&prefix=%s%s",
              encoded_container, encoded_object, trailing_slash);
    curl_free(encoded_container);
    curl_free(encoded_object);
  }

  response = send_request("GET", container, NULL, xmlctx, NULL);
  xmlParseChunk(xmlctx, "", 0, 1);
  if (xmlctx->wellFormed && response >= 200 && response < 300)
  {
    xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next)
    {
      if (onode->type != XML_ELEMENT_NODE) continue;

      char is_object = !strcasecmp((const char *)onode->name, "object");
      char is_container = !strcasecmp((const char *)onode->name, "container");
      char is_subdir = !strcasecmp((const char *)onode->name, "subdir");

      if (is_object || is_container || is_subdir)
      {
        entry_count++;

        dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
        de->name = NULL;
        de->next = NULL;
        de->size = 0;
        de->last_modified = time(NULL);
        if (is_container || is_subdir)
          de->content_type = strdup("application/directory");
        for (anode = onode->children; anode; anode = anode->next)
        {
          char *content = "<?!?>";
          for (text_node = anode->children; text_node; text_node = text_node->next)
            if (text_node->type == XML_TEXT_NODE)
              content = (char *)text_node->content;
          if (!strcasecmp((const char *)anode->name, "name"))
          {
            de->name = strdup(content + prefix_length);

            // Remove trailing slash
            char *slash = strrchr(de->name, '/');
            if (slash && (0 == *(slash + 1)))
              *slash = 0;

            if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
              de->full_name = NULL;
          }
          if (!strcasecmp((const char *)anode->name, "bytes"))
            de->size = strtoll(content, NULL, 10);
          if (!strcasecmp((const char *)anode->name, "content_type"))
          {
            de->content_type = strdup(content);
            char *semicolon = strchr(de->content_type, ';');
            if (semicolon)
              *semicolon = '\0';
          }
          if (!strcasecmp((const char *)anode->name, "last_modified"))
          {
            struct tm last_modified;
            strptime(content, "%FT%T", &last_modified);
            de->last_modified = mktime(&last_modified);
          }
        }

        // de->name still can be empty
        // ... check all properties of subdir | object
        // It can be in form <subdir name="somedir/" /> with no children
        xmlAttrPtr attr;
        for (attr = onode->properties; attr; attr = attr->next)
        {
          if (!strcasecmp((const char *)attr->name, "name"))
          {
            de->name = strdup(attr->children->content);

            // Remove trailing slash
            char *slash = strrchr(de->name, '/');
            if (slash && (0 == *(slash + 1)))
              *slash = 0;

            if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
              de->full_name = NULL;
          }
        }

        de->isdir = de->content_type &&
            ((strstr(de->content_type, "application/folder") != NULL) ||
             (strstr(de->content_type, "application/directory") != NULL));
        if (de->isdir)
        {
          if (!strncasecmp(de->name, last_subdir, sizeof(last_subdir)))
          {
            cloudfs_free_dir_list(de);
            continue;
          }
          strncpy(last_subdir, de->name, sizeof(last_subdir));
        }
        de->next = *dir_list;
        *dir_list = de;
      }
      else
      {
        debugf("unknown element: %s", onode->name);
      }
    }
    retval = 1;
  }

  debugf("entry count: %d", entry_count);

  xmlFreeDoc(xmlctx->myDoc);
  xmlFreeParserCtxt(xmlctx);
  return retval;
}

void cloudfs_free_dir_list(dir_entry *dir_list)
{
  while (dir_list)
  {
    dir_entry *de = dir_list;
    dir_list = dir_list->next;
    free(de->name);
    free(de->full_name);
    free(de->content_type);
    free(de);
  }
}

int cloudfs_delete_object(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("DELETE", encoded, NULL, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_copy_object(const char *src, const char *dst)
{
  char *dst_encoded = curl_escape(dst, 0);
  curl_slist *headers = NULL;
  add_header(&headers, "X-Copy-From", src);
  add_header(&headers, "Content-Length", "0");
  int response = send_request("PUT", dst_encoded, NULL, NULL, headers);
  curl_free(dst_encoded);
  curl_slist_free_all(headers);
  return (response >= 200 && response < 300);
}

int cloudfs_create_directory(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

off_t cloudfs_file_size(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}

void cloudfs_debug(int dbg)
{
  debug = dbg;
}

void cloudfs_verify_ssl(int vrfy)
{
  verify_ssl = vrfy;
}

static struct {
  char username[MAX_HEADER_SIZE], password[MAX_HEADER_SIZE],
       tenant[MAX_HEADER_SIZE], authurl[MAX_URL_SIZE], use_snet;
} reconnect_args;

void cloudfs_set_credentials(char *username, char *tenant, char *password, char *authurl, int use_snet)
{
  strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
  strncpy(reconnect_args.tenant, tenant, sizeof(reconnect_args.tenant));
  strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
  strncpy(reconnect_args.authurl, authurl, sizeof(reconnect_args.authurl));
  reconnect_args.use_snet = use_snet;
}

int cloudfs_connect()
{
  long response = -1;

  xmlNode *top_node = NULL, *service_node = NULL, *endpoint_node = NULL;
  xmlParserCtxtPtr xmlctx = NULL;

  char *postdata;
  if (reconnect_args.tenant[0])
  {
      int count = asprintf(&postdata,
         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
         "<auth xmlns=\"http://docs.openstack.org/identity/api/v2.0\" tenantName=\"%s\">"
         "<passwordCredentials username=\"%s\" password=\"%s\"/>"
         "</auth>",
         reconnect_args.tenant, reconnect_args.username, reconnect_args.password);
      if (count < 0)
      {
        debugf("Unable to asprintf");
        abort();
      }
  }

  pthread_mutex_lock(&pool_mut);
  debugf("Authenticating...");
  storage_token[0] = storage_url[0] = '\0';

  CURL *curl = curl_easy_init();

  curl_slist *headers = NULL;
  if (reconnect_args.tenant[0])
  {
    add_header(&headers, "Content-Type", "application/xml");
    add_header(&headers, "Accept", "application/xml");

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));

    xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
  }
  else
  {
    add_header(&headers, "X-Auth-User", reconnect_args.username);
    add_header(&headers, "X-Auth-Key", reconnect_args.password);
  }

  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
  curl_easy_setopt(curl, CURLOPT_URL, reconnect_args.authurl);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);

  curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (reconnect_args.tenant[0])
  {
    free(postdata);
    xmlParseChunk(xmlctx, "", 0, 1);
    if (xmlctx->wellFormed && response >= 200 && response < 300)
    {
      xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
      for (top_node = root_element->children; top_node; top_node = top_node->next)
      {
        if ((top_node->type == XML_ELEMENT_NODE) &&
           (!strcasecmp((const char *)top_node->name, "serviceCatalog")))
        {
          for (service_node = top_node->children; service_node; service_node = service_node->next)
            if ((service_node->type == XML_ELEMENT_NODE) &&
               (!strcasecmp((const char *)service_node->name, "service")))
            {
              xmlChar * serviceType = xmlGetProp(service_node, "type");
              int isObjectStore = serviceType && !strcasecmp(serviceType, "object-store");
              xmlFree(serviceType);

              if (!isObjectStore) continue;

              for (endpoint_node = service_node->children; endpoint_node; endpoint_node = endpoint_node->next)
                if ((endpoint_node->type == XML_ELEMENT_NODE) &&
                   (!strcasecmp((const char *)endpoint_node->name, "endpoint")))
                {
                  xmlChar * publicURL = xmlGetProp(endpoint_node, "publicURL");
                  if (publicURL)
                  {
                    char copy = 1;
                    if (storage_url[0])
                    {
                      if (strstr(publicURL, "cdn"))
                      {
                        copy = 0;
                        debugf("Warning - found multiple object-store services; keeping %s, ignoring %s",
                                                     storage_url, publicURL);
                      }
                      else
                        debugf("Warning - found multiple object-store services; using %s instead of %s",
                                                     publicURL, storage_url);
                    }
                    if (copy)
                      strncpy(storage_url, publicURL, sizeof(storage_url));
                  }
                  xmlFree(publicURL);
                }
            }
        }

        if ((top_node->type == XML_ELEMENT_NODE) &&
            (!strcasecmp((const char *)top_node->name, "token")))
        {
          xmlChar * tokenId = xmlGetProp(top_node, "id");
          if (tokenId)
          {
            if (storage_token[0])
              debugf("Warning - found multiple authentication tokens.");
            strncpy(storage_token, tokenId, sizeof(storage_token));
          }
          xmlFree(tokenId);
        }
      }
    }
    xmlFreeParserCtxt(xmlctx);
  }
  if (reconnect_args.use_snet && storage_url[0])
    rewrite_url_snet(storage_url);
  pthread_mutex_unlock(&pool_mut);
  return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}

void debugf(char *fmt, ...)
{
  if (debug)
  {
    va_list args;
    va_start(args, fmt);
    fputs("!!! ", stderr);
    vfprintf(stderr, fmt, args);
    va_end(args);
    putc('\n', stderr);
  }
}

