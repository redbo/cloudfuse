#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#ifdef __linux__
#include <alloca.h>
#endif
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <json-c/json.h>
#include "cloudfsapi.h"
#include "config.h"

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"

#define REQUEST_RETRIES 4

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static char storage_space_used[32];
static pthread_mutex_t pool_mut;
static CURL *curl_pool[1024];
static int curl_pool_count = 0;
static int debug = 0;
static int verify_ssl = 1;
static int rhel5_mode = 0;

struct json_payload {
  char *data;
  size_t size;
};

struct json_element {
  const char *e_key;
  const char *e_subkey;
  const char *e_subval;
};

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

static json_object **get_elements_from_json(struct json_element *path, json_object *root)
{
  json_object *this_obj = root, *lookup_obj = NULL;
  json_object **elements;
  int i = 0, j, len;
  int eid = 0, max_elements = 16;

  elements = (json_object **) calloc(max_elements+1, sizeof(json_object *));
  while (path[i].e_key)
  {
    if (json_object_object_get_ex(this_obj, path[i].e_key, &lookup_obj) == 0)
    {
      debugf("failed to find json element %s", path[i].e_key);
      free(elements);
      return NULL;
    }
    if (path[i].e_subkey && path[i].e_subval) // lookup_obj is an array
    {
      len = json_object_array_length(lookup_obj);
      for (j=0; j<len; ++j)
      {
        json_object *child, *sub = json_object_array_get_idx(lookup_obj, j);
	if (json_object_object_get_ex(sub, path[i].e_subkey, &child) == 0)
        {
          debugf("failed to find json element %s", path[i].e_subkey);
          free(elements);
          return NULL;
        }
        else if (!strcasecmp(path[i].e_subval, json_object_get_string(child)) ||
                 path[i].e_subval[0] == '\0') // special case to guess region
        {
          this_obj = sub;
          if (!path[i+1].e_key && eid < max_elements && j+1 < len)
          {
            elements[eid++] = sub;
            continue;
          }
          i++;
          break;
        }
      }
    }
    else
    {
      this_obj = lookup_obj;
      i++;
    }
  }
  if (eid == 0)
    elements[0] = lookup_obj;
  return elements;
}

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

static size_t json_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  struct json_payload *payload = (struct json_payload *) stream;
  size_t len = size * nmemb;

  payload->data = (char *) realloc(payload->data, payload->size+len+1);
  memcpy(&(payload->data[payload->size]), ptr, len);
  payload->size += len;
  payload->data[payload->size] = '\0';
  return len;
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

static void add_header(curl_slist **headers, const char *name,
                       const char *value)
{
  char x_header[MAX_HEADER_SIZE];
  snprintf(x_header, sizeof(x_header), "%s: %s", name, value);
  *headers = curl_slist_append(*headers, x_header);
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
    if (!strncasecmp(head, "x-auth-token", size * nmemb) ||
        !strncasecmp(head, "x-subject-token", size * nmemb))
      strncpy(storage_token, value, sizeof(storage_token));
    if (!strncasecmp(head, "x-storage-url", size * nmemb))
      strncpy(storage_url, value, sizeof(storage_url));
    if (!strncasecmp(head, "x-account-bytes-used", size * nmemb))
      strncpy(storage_space_used, value, sizeof(storage_space_used));
  }
  return size * nmemb;
}

static int send_request(char *method, const char *path, FILE *fp,
                        xmlParserCtxtPtr xmlctx, curl_slist *extra_headers)
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
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl);
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
    else if (!strcasecmp(method, "HEAD"))
    {
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
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

/*
 * Public interface
 */

void cloudfs_init()
{
  LIBXML_TEST_VERSION
  xmlXPathInit();
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

int cloudfs_tenant_info(struct statvfs *stat)
{
  int response = send_request("HEAD", "", NULL, NULL, NULL);
  if (response == 204)
  {
    fsblkcnt_t space_used = atol(storage_space_used) / stat->f_frsize;
    stat->f_bfree = stat->f_bavail = stat->f_blocks - space_used;
    return 1;
  }
  return 0;
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
      tenant[MAX_HEADER_SIZE], authurl[MAX_URL_SIZE], region[MAX_URL_SIZE],
      use_snet, auth_version;
} reconnect_args;

void cloudfs_set_credentials(char *username, char *tenant, char *password,
                             char *authurl, char *region, int use_snet)
{
  strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
  strncpy(reconnect_args.tenant, tenant, sizeof(reconnect_args.tenant));
  strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
  strncpy(reconnect_args.authurl, authurl, sizeof(reconnect_args.authurl));
  strncpy(reconnect_args.region, region, sizeof(reconnect_args.region));
  if (strstr(authurl, "v2.0"))
  {
    reconnect_args.auth_version = 2;
    if (!strcmp(authurl + strlen(authurl) - 5, "/v2.0"))
      strcat(reconnect_args.authurl, "/tokens");
    else if (!strcmp(authurl + strlen(authurl) - 6, "/v2.0/"))
      strcat(reconnect_args.authurl, "tokens");
  }
  else if (strstr(authurl, "v3"))
  {
    reconnect_args.auth_version = 3;
    if (!strcmp(authurl + strlen(authurl) - 3, "/v3"))
      strcat(reconnect_args.authurl, "/auth/tokens");
    else if (!strcmp(authurl + strlen(authurl) - 4, "/v3/"))
      strcat(reconnect_args.authurl, "auth/tokens");
  }
  else
    reconnect_args.auth_version = 1;
  reconnect_args.use_snet = use_snet;
}

int cloudfs_connect()
{
  long response = -1;
  curl_slist *headers = NULL;
  CURL *curl = curl_easy_init();
  char postdata[8192] = "";
  xmlNode *top_node = NULL, *service_node = NULL, *endpoint_node = NULL;
  xmlParserCtxtPtr xmlctx = NULL;
  enum json_tokener_error json_err = json_tokener_success;
  struct json_payload *json_payload = NULL;
  json_object *json = NULL;

  pthread_mutex_lock(&pool_mut);

  storage_token[0] = storage_url[0] = '\0';

  if (reconnect_args.auth_version == 2)
  {
    if (!reconnect_args.tenant[0]) {
      snprintf(postdata, sizeof(postdata), "{\"auth\":{\"RAX-KSKEY:apiKeyCre"
        "dentials\":{\"username\":\"%s\",\"apiKey\":\"%s\"}}}",
        reconnect_args.username, reconnect_args.password);
    } else {
      snprintf(postdata, sizeof(postdata), "{\"auth\":{\"tenantName\":\"%s\","
        "\"passwordCredentials\":{\"username\":\"%s\",\"password\":\"%s\"}}}",
        reconnect_args.tenant, reconnect_args.username,
        reconnect_args.password);
    }
    debugf("%s", postdata);

    add_header(&headers, "Content-Type", "application/json");
    add_header(&headers, "Accept", "application/json");

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
    json_payload = (struct json_payload *) calloc(1, sizeof(struct json_payload));
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &json_dispatch);
  }
  else if (reconnect_args.auth_version == 3)
  {
    if (reconnect_args.username[0] && reconnect_args.tenant[0] && reconnect_args.password[0])
    {
      snprintf(postdata, sizeof(postdata), "{\"auth\":{\"identity\":{"
          "\"methods\":[\"password\"],\"password\":{\"user\":{\"id\":"
          "\"%s\",\"password\":\"%s\"}},\"scope\":{\"project\":{\"id"
          "\":\"%s\"}}}}}", reconnect_args.username, reconnect_args.password,
          reconnect_args.tenant);
    }
    else if (reconnect_args.username[0] && reconnect_args.password[0])
    {
      snprintf(postdata, sizeof(postdata), "{\"auth\":{\"identity\":{"
          "\"methods\":[\"password\"],\"password\":{\"user\":{\"id\":"
          "\"%s\",\"password\":\"%s\"}}}}}", reconnect_args.username,
          reconnect_args.password);
    }
    debugf("%s", postdata);
    add_header(&headers, "Content-Type", "application/json");

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);

    json_payload = (struct json_payload *) calloc(1, sizeof(struct json_payload));
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &json_dispatch);
  }
  else
  {
    add_header(&headers, "X-Auth-User", reconnect_args.username);
    add_header(&headers, "X-Auth-Key", reconnect_args.password);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
  }

  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
  curl_easy_setopt(curl, CURLOPT_URL, reconnect_args.authurl);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);

  debugf("Sending authentication request.");
  curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (reconnect_args.auth_version == 2 && json_payload)
  {
    json = json_tokener_parse_verbose(json_payload->data, &json_err);
    free(json_payload->data);
    free(json_payload);
    if (!reconnect_args.region[0])
    {
      json_object *access, *user, *default_region;
      if (json_object_object_get_ex(json, "access", &access) &&
          json_object_object_get_ex(access, "user", &user) &&
          json_object_object_get_ex(user, "RAX-AUTH:defaultRegion", &default_region))
      {
        strncpy(reconnect_args.region, json_object_get_string(default_region), sizeof(reconnect_args.region));
      }
    }
    json_object *access, *service_catalog, *token, *id;
    if (json_object_object_get_ex(json, "access", &access) &&
        json_object_object_get_ex(access, "token", &token) &&
        json_object_object_get_ex(token, "id", &id))
    {
      strncpy(storage_token, json_object_get_string(id), sizeof(storage_token));
    }
    if (json_object_object_get_ex(json, "access", &access) &&
        json_object_object_get_ex(access, "serviceCatalog", &service_catalog))
    {
      int i, entries = json_object_array_length(service_catalog);
      for (i = 0; i < entries; i++)
      {
        json_object *type, *catalog_entry = json_object_array_get_idx(service_catalog, i);
        if (json_object_object_get_ex(catalog_entry, "type", &type))
        {
          const char *type_name = json_object_get_string(type);
          if (!strcmp(type_name, "object-store"))
          {
            json_object *endpoints;
            if (json_object_object_get_ex(catalog_entry, "endpoints", &endpoints))
            {
              int i, entries = json_object_array_length(endpoints);
              for (i = 0; i < entries; i++)
              {
                json_object *url, *region, *endpoint = json_object_array_get_idx(endpoints, i);
                if (json_object_object_get_ex(endpoint, "region", &region))
                {
                  const char *region_name = json_object_get_string(region);
                  if (reconnect_args.region[0] == 0 ||
                      !strncmp(region_name, reconnect_args.region, sizeof(reconnect_args.region)))
                  {
                    if (reconnect_args.use_snet &&
                        json_object_object_get_ex(endpoint, "internalURL", &url))
                    {
                      strncpy(storage_url, json_object_get_string(url), sizeof(storage_url));
                    } else if (json_object_object_get_ex(endpoint, "publicURL", &url)) {
                      strncpy(storage_url, json_object_get_string(url), sizeof(storage_url));
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    json_object_put(json);
    debugf("storage_url: %s", storage_url);
    debugf("storage_token: %s", storage_token);
  }
  else if (reconnect_args.auth_version == 3)
  {
    if (json_payload)
    {
      json = json_tokener_parse_verbose(json_payload->data, &json_err);
      free(json_payload->data);
      free(json_payload);
      if (json_err != json_tokener_success)
        debugf("failed parsing the JSON stream");
      else
      {
        struct json_element path[] = {
          { .e_key="token" },
          { .e_key="catalog", .e_subkey="type", .e_subval="object-store" },
          { .e_key="endpoints", .e_subkey="region_id", .e_subval=reconnect_args.region },
          { .e_key=NULL }
        };
        json_object **ep = get_elements_from_json(path, json);
        if (ep)
        {
          int ep_id;
          char is_public, is_internal;
          char wants_internal = reconnect_args.use_snet;
          for (ep_id=0; ep[ep_id]; ++ep_id)
          {
            json_object *interface = NULL, *url = NULL;
            json_object_object_get_ex(ep[ep_id], "url", &url);
            json_object_object_get_ex(ep[ep_id], "interface", &interface);
            is_internal = strcasecmp(json_object_get_string(interface), "internal") == 0;
            is_public = is_internal ? 0 : strcasecmp(json_object_get_string(interface), "public") == 0;
            if ((wants_internal && is_internal) || (!wants_internal && is_public))
            {
              strncpy(storage_url, json_object_get_string(url), sizeof(storage_url));
              break;
            }
          }
          free(ep);
        }
      }
      json_object_put(json);
      debugf("storage_url: %s", storage_url);
      debugf("storage_token: %s", storage_token);
    }
  }
  else if (reconnect_args.use_snet && storage_url[0])
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

