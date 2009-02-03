#define _GNU_SOURCE // for strcasestr
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <alloca.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include "cloudfsapi.h"
#include "config.h"

static char saved_username[MAX_HEADER_SIZE];
static char saved_password[MAX_HEADER_SIZE];
static char saved_authurl[MAX_URL_SIZE];
static char storage_url[MAX_HEADER_SIZE];
char storage_token[MAX_HEADER_SIZE];
static FILE *devnull = NULL;

static CURL *curl_pool[1024];
static int curl_pool_count;
static pthread_mutex_t mut;
static pthread_mutexattr_t mattr;
static CURL *get_curl_obj()
{
  static int initialized = 0;
  if (!initialized)
  {
    curl_pool_count = 0;
    curl_global_init(CURL_GLOBAL_ALL);
    pthread_mutexattr_init(&mattr);
    pthread_mutex_init(&mut, &mattr);
    initialized = 1;
  }
  pthread_mutex_lock(&mut);
  CURL *curl;
  if (curl_pool_count == 0)
    curl = curl_easy_init();
  else
    curl = curl_pool[--curl_pool_count];
  pthread_mutex_unlock(&mut);
  return curl;
}

static void release_curl_obj(CURL *curl)
{
  pthread_mutex_lock(&mut);
  curl_easy_reset(curl);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&mut);
}

static dispatcher *dispatch_init()
{
  dispatcher *d = (dispatcher *)malloc(sizeof(dispatcher));
  d->header_callback = NULL;
  d->data_callback = NULL;
  d->write_fp = NULL;
  d->read_fp = NULL;
  d->content_length = 0;
  d->buffer = NULL;
  d->buffer_size = 2048;
  d->buffer_len = 0;
  d->list = NULL;
  d->xmlctx = NULL;
  return d;
}

static void dispatch_free(dispatcher *d)
{
  if (d->xmlctx)
  {
    xmlFreeDoc(d->xmlctx->myDoc);
    xmlFreeParserCtxt(d->xmlctx);
  }
  if (d->list)
    curl_slist_free_all(d->list);
  if (d->buffer)
    free(d->buffer);
  free(d);
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
    dispatcher *d = (dispatcher *)stream;
    if (d && d->header_callback)
      d->header_callback(d, head, value);
  }
  return size * nmemb;
}

static size_t data_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  dispatcher *d = (dispatcher *)stream;
  if (d && d->data_callback)
    d->data_callback(d, (char *)ptr, size * nmemb);
  return size * nmemb;
}

static void newline_split(struct dispatcher *d, char *data, int length)
{
  while (!d->buffer || (d->buffer_len + length) > d->buffer_size)
  {
    char *newbuf = (char *)malloc(d->buffer_size *= 2), *oldbuf = d->buffer;
    memcpy(newbuf, oldbuf, d->buffer_len);
    if (oldbuf)
      free(oldbuf);
    d->buffer = newbuf;
  }
  memcpy(&d->buffer[d->buffer_len], data, length);
  d->buffer_len += length;
  char *line_break;
  while ((line_break = (char *)memchr(d->buffer, '\n', d->buffer_len)))
  {
    int record_len = line_break - d->buffer;
    char *label = (char *)alloca(record_len + 1);
    sscanf(d->buffer, "%[^\n\r]", label);
    while (*label <= ' ')
      label++;
    while (*label && label[strlen(label) - 1] <= ' ')
      label[strlen(label) - 1] = 0;
    if (label[0])
      d->list = curl_slist_append(d->list, label);
    memmove(d->buffer, line_break + 1, d->buffer_len -= record_len + 1);
  }
}

static void feed_xml(struct dispatcher *d, char *data, int length)
{
  xmlParseChunk(d->xmlctx, data, length, 0);
}

static void authentication_headers(struct dispatcher *d, char *header, char *val)
{
  if (!strcasecmp(header, "x-auth-token"))
    strncpy(storage_token, val, sizeof(storage_token));
  if (!strcasecmp(header, "x-storage-url"))
    strncpy(storage_url, val, sizeof(storage_url));
}

static int send_request(char *method, curl_slist *headers, dispatcher *callback, const char *path)
{
  char url[MAX_URL_SIZE];
  int response = -1;

  char *slash;
  while ((slash = strcasestr(path, "%2F")))
  {
    *slash = '/';
    memmove(slash+1, slash+3, strlen(slash+3)+1);
  }
  if (storage_url[0])
  {
    while (*path == '/')
      path++;
    strncpy(url, storage_url, sizeof(url));
    strncat(url, "/", sizeof(url));
    strncat(url, path, sizeof(url));
  }
  else
    strncpy(url, path, sizeof(url));

  if (storage_token[0])
  {
    char storage_token_header[MAX_HEADER_SIZE];
    snprintf(storage_token_header, sizeof(storage_token_header), "X-Auth-Token: %s", storage_token);
    headers = curl_slist_append(headers, storage_token_header);
  }

  CURL *curl = get_curl_obj();
  if (!strcasecmp(method, "MKDIR"))
  {
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
    curl_easy_setopt(curl, CURLOPT_READDATA, devnull);
    headers = curl_slist_append(headers, "Content-Type: application/directory");
  }
  else if (!strcasecmp(method, "PUT") && callback && callback->read_fp)
  {
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, callback->content_length);
    curl_easy_setopt(curl, CURLOPT_READDATA, callback->read_fp);
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
  }
  else if (!strcasecmp(method, "HEAD"))
  {
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  }
  else
  {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  }
  headers = curl_slist_append(headers, "Expect:");
  curl_easy_setopt(curl, CURLOPT_VERBOSE, DEBUG);
  curl_easy_setopt(curl, CURLOPT_WRITEHEADER, callback);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 4);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_dispatch);
  if (callback && callback->write_fp)
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, callback->write_fp);
  else
  {
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &data_dispatch);
  }
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  if (response == 401 && cloudfs_connect(saved_username, saved_password, saved_authurl))
  {
    if (callback && callback->write_fp)
    {
      fflush(callback->write_fp);
      rewind(callback->write_fp);
      ftruncate(fileno(callback->write_fp), 0);
    }
    return send_request(method, NULL, callback, path);
  }
  curl_slist_free_all(headers);
  release_curl_obj(curl);
  return response;
}

/*
 * Public interface
 */

int object_read_from(const char *path, FILE *fp)
{
  struct stat buf;
  fflush(fp);
  rewind(fp);
  fstat(fileno(fp), &buf);
  dispatcher *d = dispatch_init();
  d->content_length = buf.st_size;
  d->read_fp = fp;
  char *encoded = curl_escape(path, 0);
  int response = send_request("PUT", NULL, d, encoded);
  curl_free(encoded);
  dispatch_free(d);
  return (response >= 200 && response < 300);
}

int object_write_to(const char *path, FILE *fp)
{
  dispatcher *d = dispatch_init();
  d->write_fp = fp;
  char *encoded = curl_escape(path, 0);
  int response = send_request("GET", NULL, d, encoded);
  curl_free(encoded);
  dispatch_free(d);
  fflush(fp);
  if (response >= 200 && response < 300)
    return 1;
  ftruncate(fileno(fp), 0);
  rewind(fp);
  return 0;
}

int object_truncate(const char *path)
{
  dispatcher *d = dispatch_init();
  d->write_fp = devnull;
  char *encoded = curl_escape(path, 0);
  int response = send_request("GET", NULL, d, encoded);
  curl_free(encoded);
  dispatch_free(d);
  if (response >= 200 && response < 300)
    return 1;
  return 0;
}

int list_directory(const char *path, dir_entry **dir_list)
{
  char container[MAX_PATH_SIZE * 3];
  char object[MAX_PATH_SIZE];
  int response = 0;
  dispatcher *d = dispatch_init();
  *dir_list = NULL;
  if (!strcmp(path, "") || !strcmp(path, "/"))
  {
    d->list = NULL;
    d->data_callback = newline_split;
    response = send_request("GET", NULL, d, "/");
    if (response < 200 || response >= 300)
      return 0;
    curl_slist *tmp;
    for (tmp = d->list; tmp; tmp = tmp->next)
    {
      dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
      de->name = strdup(tmp->data);
      asprintf(&(de->full_name), "/%s", de->name);
      de->content_type = strdup("application/directory");
      de->size = 0;
      de->last_modified = time(NULL);
      de->isdir = 1;
      de->next = *dir_list;
      *dir_list = de;
    }
    dispatch_free(d);
    return 1;
  }
  if (sscanf(path, "/%[^/]/%[^\n]", container, object) == 1)
    strncpy(object, "", sizeof(object));
  d->xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  d->data_callback = feed_xml;
  char *encoded_container = curl_escape(container, 0);
  char *encoded_object = curl_escape(object, 0);
  strncpy(container, encoded_container, sizeof(container));
  strncat(container, "?format=xml&path=", sizeof(container));
  strncat(container, encoded_object, sizeof(container));
  curl_free(encoded_container);
  curl_free(encoded_object);
  response = send_request("GET", NULL, d, container);
  xmlParseChunk(d->xmlctx, "", 0, 1);
  if (d->xmlctx->wellFormed && response >= 200 && response < 300)
  {
    xmlNode *root_element = xmlDocGetRootElement(d->xmlctx->myDoc);
    xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
    for (onode = root_element->children; onode; onode = onode->next)
      if ((onode->type == XML_ELEMENT_NODE) && !strcasecmp((const char *)onode->name, "object"))
      {
        dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
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
            asprintf(&(de->full_name), "%s/%s", path, de->name);
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
            ((strcasestr(de->content_type, "application/folder") != NULL) ||
             (strcasestr(de->content_type, "application/directory") != NULL));
        de->next = *dir_list;
        *dir_list = de;
      }
    dispatch_free(d);
    return 1;
  }
  dispatch_free(d);
  return 0;
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
  int response = send_request("DELETE", NULL, NULL, encoded);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int create_directory(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", NULL, NULL, encoded);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_connect(char *username, char *password, char *authurl)
{
  static int initialized = 0;
  struct curl_slist *headers = NULL;
  int response = 0;
  char x_user[MAX_HEADER_SIZE], x_pass[MAX_HEADER_SIZE];

  if (!initialized)
  {
    LIBXML_TEST_VERSION
    strncpy(saved_username, username, sizeof(saved_username));
    strncpy(saved_password, password, sizeof(saved_password));
    strncpy(saved_authurl, authurl, sizeof(saved_password));
    devnull = fopen("/dev/null", "r");
    initialized = 1;
  }
  snprintf(x_user, sizeof(x_user), "X-Auth-User: %s", username);
  headers = curl_slist_append(headers, x_user);
  snprintf(x_pass, sizeof(x_pass), "X-Auth-Key: %s", password);
  headers = curl_slist_append(headers, x_pass);
  storage_token[0] = storage_url[0] = '\0';
  dispatcher *d = dispatch_init();
  d->header_callback = authentication_headers;
  response = send_request("GET", headers, d, authurl);
  dispatch_free(d);
  return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}

