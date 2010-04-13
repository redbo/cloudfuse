#define _GNU_SOURCE
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
#include <libxml/tree.h>
#include "cloudfsapi.h"
#include "config.h"

#ifdef HAVE_LIBMAGIC
#include <magic.h>
static magic_t magic_cookie;
#endif

struct {
  char username[MAX_HEADER_SIZE];
  char password[MAX_HEADER_SIZE];
  char authurl[MAX_URL_SIZE];
  int use_snet;
} reconnect_args;
static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static FILE *devnull = NULL;
static pthread_mutex_t pool_mut;
static pthread_mutexattr_t pool_matter;
typedef const char *extension[2];
static extension *extensions = NULL;
static int ext_size = 0;
static int ext_count = 0;
static int debug = 0;

static void add_mime_type(char *ext, char *type)
{
  if ((ext_count + 1) > ext_size)
    extensions = realloc(extensions, (ext_size += 100) * sizeof(extension));
  extensions[ext_count][0] = strdup(ext);
  extensions[ext_count++][1] = strdup(type);
}

void load_mimetypes(const char *filename)
{
  int i, count;
  FILE *fp;
  char line[1024], type[sizeof(line)], ext[7][sizeof(line)], *comment;
  char *common_types[][2] = {
    {"gif", "image/gif"}, {"png", "image/png"}, {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"}, {"css", "text/css"}, {"xml", "text/xml"},
    {"html", "text/html"}, {"htm", "text/html"}, {"txt", "text/plain"},
    {"bmp", "image/x-ms-bmp"}, {"mpeg", "video/mpeg"}, {"mpg", "video/mpeg"},
    {"mov", "video/quicktime"}, {"mp3", "audio/mpeg"}, {"wav", "audio/x-wav"},
    {"doc", "application/msword"}, {"ppt", "application/vnd.ms-powerpoint"},
    {"zip", "application/zip"}, {"js", "application/x-javascript"},
    {"pdf", "application/pdf"}, {"xhtml", "application/xhtml+xml"}, {NULL}
  };
  for (i = 0; common_types[i][0]; i++)
    add_mime_type(common_types[i][0], common_types[i][1]);
  if (!(fp = fopen(filename, "r")))
    return;
  while (fgets(line, sizeof(line), fp))
  {
    if ((comment = strstr(line, "#")))
      *comment = '\0';
    count = sscanf(line, " %s %s %s %s %s %s %s %s ", type, ext[0], ext[1],
            ext[2], ext[3], ext[4], ext[5], ext[6]);
    for (i = 0; i < count - 1; i++)
      add_mime_type(ext[i], type);
  }
  fclose(fp);
}

static const char *file_content_type(FILE *fp, const char *path)
{
  int i;
  const char *ext;
  if ((ext = rindex(path, '.')) && *(++ext))
    for (i = 0; i < ext_count; i++)
      if (!strcasecmp(extensions[i][0], ext))
        return extensions[i][1];
#ifdef HAVE_LIBMAGIC
  char buf[1024];
  i = fread(buf, 1, sizeof(buf), fp);
  rewind(fp);
  if ((ext = magic_buffer(magic_cookie, buf, i)))
    return ext;
#endif
  return "application/octet-stream";
}

void rewrite_url_snet(char *url)
{
  char protocol[MAX_URL_SIZE];
  char rest[MAX_URL_SIZE];
  sscanf(url, "%[a-z]://%s", protocol, rest);
  if (strncasecmp(rest, "snet-", 5))
    sprintf(url, "%s://snet-%s", protocol, rest);
}

typedef struct dispatcher
{
  FILE *write_fp;
  FILE *read_fp;
  int content_length;
  xmlParserCtxtPtr xmlctx;
} dispatcher;

static dispatcher *dispatch_init()
{
  dispatcher *d = (dispatcher *)malloc(sizeof(dispatcher));
  d->write_fp = NULL;
  d->read_fp = NULL;
  d->content_length = 0;
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
  free(d);
}

static void dispatch_clear(dispatcher *d)
{
  d->content_length = 0;
  if (d->xmlctx)
  {
    xmlFreeDoc(d->xmlctx->myDoc);
    xmlFreeParserCtxt(d->xmlctx);
    d->xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  }
  if (d->write_fp)
  {
    fflush(d->write_fp);
    rewind(d->write_fp);
    ftruncate(fileno(d->write_fp), 0);
  }
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

static size_t data_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  dispatcher *d = (dispatcher *)stream;
  if (d && d->xmlctx)
    xmlParseChunk(d->xmlctx, (char *)ptr, size * nmemb, 0);
  return size * nmemb;
}

static int send_request(char *method, curl_slist *headers, dispatcher *callback, const char *path)
{
  static CURL *curl_pool[1024];
  static int curl_pool_count = 0;
  char url[MAX_URL_SIZE];
  long response = -1;

  char *slash;
  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
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

  pthread_mutex_lock(&pool_mut);
  CURL *curl = curl_pool_count ? curl_pool[--curl_pool_count] : curl_easy_init();
  pthread_mutex_unlock(&pool_mut);

  if (!strcasecmp(method, "MKDIR"))
  {
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
    curl_easy_setopt(curl, CURLOPT_READDATA, devnull);
    headers = curl_slist_append(headers, "Content-Type: application/directory");
  }
  else if (!strcasecmp(method, "PUT") && callback && callback->read_fp)
  {
    char content_type_header[MAX_HEADER_SIZE];
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, callback->content_length);
    curl_easy_setopt(curl, CURLOPT_READDATA, callback->read_fp);
    snprintf(content_type_header, sizeof(content_type_header),
        "Content-Type: %s", file_content_type(callback->read_fp, path));
    headers = curl_slist_append(headers, content_type_header);
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
  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
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
  if (response == 401 && storage_token[0] &&
      cloudfs_connect(reconnect_args.username, reconnect_args.password,
                      reconnect_args.authurl, reconnect_args.use_snet))
  {
    if (callback)
      dispatch_clear(callback);
    return send_request(method, NULL, callback, path);
  }
  curl_slist_free_all(headers);
  curl_easy_reset(curl);
  pthread_mutex_lock(&pool_mut);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&pool_mut);
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
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  int response = 0;
  dispatcher *d = dispatch_init();
  *dir_list = NULL;
  xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
  d->xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
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
    strncpy(container, encoded_container, sizeof(container));
    strncat(container, "?format=xml&path=", sizeof(container));
    strncat(container, encoded_object, sizeof(container));
    curl_free(encoded_container);
    curl_free(encoded_object);
  }
  response = send_request("GET", NULL, d, container);
  xmlParseChunk(d->xmlctx, "", 0, 1);
  if (d->xmlctx->wellFormed && response >= 200 && response < 300)
  {
    xmlNode *root_element = xmlDocGetRootElement(d->xmlctx->myDoc);
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
            ((strstr(de->content_type, "application/folder") != NULL) ||
             (strstr(de->content_type, "application/directory") != NULL));
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

void cloudfs_debug(int dbg)
{
  debug = dbg;
}

int cloudfs_connect(char *username, char *password, char *authurl, int use_snet)
{
  static int initialized = 0;
  struct curl_slist *headers = NULL;
  int response = 0;
  char x_user[MAX_HEADER_SIZE], x_pass[MAX_HEADER_SIZE];

  if (!initialized)
  {
    LIBXML_TEST_VERSION
    curl_global_init(CURL_GLOBAL_ALL);
    pthread_mutexattr_init(&pool_matter);
    pthread_mutex_init(&pool_mut, &pool_matter);
    strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
    strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
    strncpy(reconnect_args.authurl, authurl, sizeof(reconnect_args.authurl));
    reconnect_args.use_snet = use_snet;
    devnull = fopen("/dev/null", "r");
    #ifdef HAVE_LIBMAGIC
    magic_cookie = magic_open(MAGIC_MIME);
    if (magic_load(magic_cookie, NULL))
      if (magic_load(magic_cookie, "/usr/share/misc/magic"))
         magic_load(magic_cookie, "/usr/share/file/magic");
    #endif
    initialized = 1;
  }
  snprintf(x_user, sizeof(x_user), "X-Auth-User: %s", username);
  headers = curl_slist_append(headers, x_user);
  snprintf(x_pass, sizeof(x_pass), "X-Auth-Key: %s", password);
  headers = curl_slist_append(headers, x_pass);
  storage_token[0] = storage_url[0] = '\0';
  dispatcher *d = dispatch_init();
  response = send_request("GET", headers, d, authurl);
  dispatch_free(d);
  if (use_snet && storage_url[0])
    rewrite_url_snet(storage_url);
  return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}

