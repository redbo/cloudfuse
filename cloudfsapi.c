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
#include <sys/time.h>
#include <libxml/tree.h>
#include "cloudfsapi.h"
#include "config.h"

#ifdef HAVE_LIBMAGIC
#include <magic.h>
static magic_t magic_cookie;
#endif

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
static CURL *curl_pool[1024];
static int curl_pool_count = 0;
static char *(*extensions)[2] = NULL;
static int debug = 0;

static void add_mime_type(char *ext, char *type)
{
  static int ext_size = 0;
  static int ext_count = 0;
  if ((ext_count + 2) > ext_size)
    extensions = realloc(extensions, (ext_size += 100) * sizeof(char *) * 2);
  extensions[ext_count+1][0] = NULL;
  extensions[ext_count][0] = strdup(ext);
  extensions[ext_count++][1] = strdup(type);
}

static const char *file_content_type(FILE *fp, const char *path)
{
  int i;
  const char *ext;
  if ((ext = rindex(path, '.')) && *(++ext))
    for (i = 0; extensions[i][0]; i++)
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
  if (!storage_url[0])
  {
    debugf("get_connection with no storage_url?");
    abort();
  }
  pthread_mutex_lock(&pool_mut);
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

static int send_request(char *method, const char *path, FILE *fp, xmlParserCtxtPtr xmlctx)
{
  long response = -1;
  CURL *curl = get_connection(path);
  curl_slist *headers = NULL;
  add_header(&headers, "X-Auth-Token", storage_token);

  if (!strcasecmp(method, "MKDIR"))
  {
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
    add_header(&headers, "Content-Type", "application/directory");
  }
  else if (!strcasecmp(method, "PUT") && fp)
  {
    char x_header[MAX_HEADER_SIZE];
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_size(fileno(fp)));
    curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    add_header(&headers, "Content-Type", file_content_type(fp, path));
  }
  else if (!strcasecmp(method, "HEAD"))
  {
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  }
  else
  {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (xmlctx)
    {
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
    }
    else if (fp)
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  if (response >= 500 || response == 401) // retry on failures
  {
    struct timeval wait = {5, 0}; // sleep 5 seconds
    select(0, NULL, NULL, NULL, &wait);
    if (response == 401) // re-authenticate on 401s
    {
      char x_header[MAX_HEADER_SIZE];
      debugf("Re-authenticating");
      if (!cloudfs_connect(0, 0, 0, 0))
        return response;
      add_header(&headers, "X-Auth-Token", "");
      add_header(&headers, "X-Auth-Token", storage_token);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    if (xmlctx)
    {
      xmlFreeDoc(xmlctx->myDoc);
      xmlFreeParserCtxt(xmlctx);
      xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
    }
    if (fp)
      rewind(fp);
    debugf("Attempting request again");
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  }
  curl_slist_free_all(headers);
  return_connection(curl);
  return response;
}

/*
 * Public interface
 */

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
    {"pdf", "application/pdf"}, {"xhtml", "application/xhtml+xml"},
    {"swf", "application/x-shockwave-flash"}, {"avi", "video/x-msvideo"},
    {"jar", "application/java-archive"}, {"7z", "application/x-7z-compressed"},
    {"rar", "application/rar"}, {"iso", "application/x-iso9660-image"},
    {"tar", "application/x-tar"}, {NULL}
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

int object_read_fp(const char *path, FILE *fp)
{
  fflush(fp);
  rewind(fp);
  char *encoded = curl_escape(path, 0);
  int response = send_request("PUT", encoded, fp, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int object_write_fp(const char *path, FILE *fp)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("GET", encoded, fp, NULL);
  curl_free(encoded);
  fflush(fp);
  if (response >= 200 && response < 300)
    return 1;
  ftruncate(fileno(fp), 0);
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
    response = send_request("PUT", encoded, fp, NULL);
    fclose(fp);
  }
  else
  {//TODO: this is busted
    response = send_request("GET", encoded, NULL, NULL);
  }
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int list_directory(const char *path, dir_entry **dir_list)
{
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  int response = 0;
  int retval = 0;
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
    snprintf(container, sizeof(container), "%s?format=xml&path=%s",
              encoded_container, encoded_object);
    curl_free(encoded_container);
    curl_free(encoded_object);
  }
  response = send_request("GET", container, NULL, xmlctx);
  xmlParseChunk(xmlctx, "", 0, 1);
  if (xmlctx->wellFormed && response >= 200 && response < 300)
  {
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
      }
    retval = 1;
  }
  xmlFreeDoc(xmlctx->myDoc);
  xmlFreeParserCtxt(xmlctx);
  return retval;
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
  int response = send_request("DELETE", encoded, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int create_directory(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

void cloudfs_debug(int dbg)
{
  debug = dbg;
}

size_t file_size(int fd)
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
  char x_header[MAX_HEADER_SIZE];
  static int initialized = 0;

  if (!initialized)
  {
    LIBXML_TEST_VERSION
    curl_global_init(CURL_GLOBAL_ALL);
    pthread_mutex_init(&pool_mut, NULL);
    strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
    strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
    strncpy(reconnect_args.authurl, authurl, sizeof(reconnect_args.authurl));
    reconnect_args.use_snet = use_snet;
    #ifdef HAVE_LIBMAGIC
    magic_cookie = magic_open(MAGIC_MIME);
    if (magic_load(magic_cookie, NULL))
      if (magic_load(magic_cookie, "/usr/share/misc/magic"))
         magic_load(magic_cookie, "/usr/share/file/magic");
    #endif
    initialized = 1;
  }
  else
  {
    username = reconnect_args.username;
    password = reconnect_args.password;
    authurl = reconnect_args.authurl;
    use_snet = reconnect_args.use_snet;
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
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (use_snet && storage_url[0])
    rewrite_url_snet(storage_url);
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

