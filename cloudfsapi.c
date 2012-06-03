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

#define REQUEST_RETRIES 4

// defined by Rackspace
#define MAX_RESULTS_PER_REQUEST 10000

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
static CURL *curl_pool[1024];
static int curl_pool_count = 0;
static int debug = 0;

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

void init_locks()
{
  pthread_mutex_init(&pool_mut, NULL);
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
  char url[MAX_URL_SIZE];
  pthread_mutex_lock(&pool_mut);
  if (!storage_url[0])
  {
    debugf("get_connection with no storage_url?");
    abort();
  }
  CURL *curl = curl_pool_count ? curl_pool[--curl_pool_count] : curl_easy_init();
  if (!curl)
  {
    debugf("curl alloc failed");
    abort();
  }
  pthread_mutex_unlock(&pool_mut);
  char *slash;
  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
  {
    *slash = '/';
    memmove(slash+1, slash+3, strlen(slash+3)+1);
  }
  while (*path == '/')
    path++;
  snprintf(url, sizeof(url), "%s/%s", storage_url, path);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
  return curl;
}

static void return_connection(CURL *curl)
{
  curl_easy_reset(curl);
  pthread_mutex_lock(&pool_mut);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&pool_mut);
}

void add_header(curl_slist **headers, const char *name, const char *value)
{
  char x_header[MAX_HEADER_SIZE];
  snprintf(x_header, sizeof(x_header), "%s: %s", name, value);
  *headers = curl_slist_append(*headers, x_header);
}

static int send_request(char *method, const char *path, FILE *fp, xmlParserCtxtPtr xmlctx, curl_slist *extra_headers)
{
  long response = -1;
  int tries = 0;

  // retry on failures
  for (tries = 0; tries < REQUEST_RETRIES; tries++)
  {
    CURL *curl = get_connection(path);
    curl_slist *headers = NULL;
    add_header(&headers, "X-Auth-Token", storage_token);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
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
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size(fileno(fp)));
      curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    }
    else if (!strcasecmp(method, "GET"))
    {
      if (fp)
      {
        rewind(fp); // make sure the file is ready for a-writin'
        fflush(fp);
        ftruncate(fileno(fp), 0);
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
    return_connection(curl);
    if (response >= 200 && response < 400)
      return response;
    sleep(8 << tries); // backoff
    if (response == 401 && !cloudfs_connect(0, 0, 0, 0)) // re-authenticate on 401s
      return response;
    if (xmlctx)
      xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);
  }
  return response;
}

/*
 * Public interface
 */

int object_read_fp(const char *path, FILE *fp)
{
  fflush(fp);
  rewind(fp);
  char *encoded = curl_escape(path, 0);
  int response = send_request("PUT", encoded, fp, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int object_write_fp(const char *path, FILE *fp)
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

int object_truncate(const char *path, off_t size)
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

int list_directory_internal(const char *path, dir_entry **dir_list)
{
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  int response = 0;
  int retval = -1;
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
    snprintf(container, sizeof(container), "%s?format=xml&path=%s",
              encoded_container, encoded_object);
    curl_free(encoded_container);
    curl_free(encoded_object);
  }
  if (*dir_list != NULL) {
    strcat(container, "&marker=");
    strcat(container, (*dir_list)->marker);
  }
  printf("%s\n", container);
  response = send_request("GET", container, NULL, xmlctx, NULL);
  xmlParseChunk(xmlctx, "", 0, 1);
  if (xmlctx->wellFormed && response >= 200 && response < 300)
  {
    retval = 0;
    xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next)
      if ((onode->type == XML_ELEMENT_NODE) &&
         (!strcasecmp((const char *)onode->name, "object") || !strcasecmp((const char *)onode->name, "container")))
      {
        dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
        de->size = 0;
        de->last_modified = time(NULL);
        if (!strcasecmp((const char *)onode->name, "container"))
          de->content_type = strdup("application/directory");
        for (anode = onode->children; anode; anode = anode->next)
        {
          char *content = "<?!?>";
          for (text_node = anode->children; text_node; text_node = text_node->next)
            if (text_node->type == XML_TEXT_NODE)
              content = (char *)text_node->content;
          if (!strcasecmp((const char *)anode->name, "name"))
          {
            if (strrchr(content, '/'))
              de->name = strdup(strrchr(content, '/')+1);
            else
              de->name = strdup(content);
            de->marker = strdup(content);
            if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
              de->full_name = NULL;
          }
          if (!strcasecmp((const char *)anode->name, "bytes"))
            de->size = atoi(content);
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
        de->next = *dir_list;
        *dir_list = de;
        retval++;
      }
  }
  xmlFreeDoc(xmlctx->myDoc);
  xmlFreeParserCtxt(xmlctx);
  return retval;
}

int list_directory(const char *path, dir_entry **dir_list)
{
  int retval;
  *dir_list = NULL;

  do {
    retval = list_directory_internal(path, dir_list);
  } while(retval == MAX_RESULTS_PER_REQUEST);

  return retval == -1 ? 0 : 1;
}

void free_dir_list(dir_entry *dir_list)
{
  while (dir_list)
  {
    dir_entry *de = dir_list;
    dir_list = dir_list->next;
    free(de->name);
    free(de->content_type);
    free(de);
  }
}

int delete_object(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("DELETE", encoded, NULL, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int copy_object(const char *src, const char *dst)
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

int create_directory(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

void cloudfs_debug(int dbg)
{
  debug = dbg;
}

off_t file_size(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}

int cloudfs_connect(char *username, char *password, char *authurl, int use_snet)
{
  static struct {
    char username[MAX_HEADER_SIZE], password[MAX_HEADER_SIZE],
         authurl[MAX_URL_SIZE], use_snet;
  } reconnect_args;

  long response = -1;
  static int initialized = 0;

  if (!initialized)
  {
    LIBXML_TEST_VERSION
    init_locks();
    curl_global_init(CURL_GLOBAL_ALL);
    strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
    strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
    strncpy(reconnect_args.authurl, authurl, sizeof(reconnect_args.authurl));
    reconnect_args.use_snet = use_snet;
    initialized = 1;
  }
  else
  {
    username = reconnect_args.username;
    password = reconnect_args.password;
    authurl = reconnect_args.authurl;
    use_snet = reconnect_args.use_snet;
  }

  
  pthread_mutex_lock(&pool_mut);
  debugf("Authenticating...");
  storage_token[0] = storage_url[0] = '\0';
  curl_slist *headers = NULL;
  add_header(&headers, "X-Auth-User", username);
  add_header(&headers, "X-Auth-Key", password);
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
  curl_easy_setopt(curl, CURLOPT_URL, authurl);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
  curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (use_snet && storage_url[0])
    rewrite_url_snet(storage_url);
  pthread_mutex_unlock(&pool_mut);
  return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}

size_t header_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
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

