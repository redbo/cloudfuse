#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#if !defined(DEBUG)
#define DEBUG 0
#endif
#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 4096
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define MAX_URL_SIZE (MAX_PATH_SIZE * 3)
#define USER_AGENT "CloudFuse"

typedef struct curl_slist curl_slist;

typedef struct dir_entry
{
  char *name;
  char *full_name;
  char *content_type;
  unsigned long size;
  time_t last_modified;
  int isdir;
  struct dir_entry *next;
} dir_entry;

int object_read_from(const char *path, FILE *fp);
int object_write_to(const char *path, FILE *fp);
int list_directory(const char *path, dir_entry **);
int delete_object(const char *path);
int create_directory(const char *label);
int cloudfs_connect(char *username, char *password, char *authurl, int snet_rewrite);
void free_dir_list(dir_entry *dir_list);
int object_truncate(const char *path);
#endif

