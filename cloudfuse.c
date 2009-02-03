#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include "cloudfsapi.h"
#include "config.h"

#define CACHE_TIMEOUT 600

typedef struct dir_cache
{
  char *path;
  dir_entry *entries;
  time_t cached;
  struct dir_cache *next, *prev;
} dir_cache;
static dir_cache *dcache;
static pthread_mutex_t dmut;
static pthread_mutexattr_t dmattr;

/*
int hash_string(const char *data)
{
  uint32_t a = 1, b = 0;
  for (; *data; data++)
  {
    a = (a + *(unsigned char *)data) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) % HASH_SIZE;
}
*/

static int file_size(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}

static void dir_for(const char *path, char *dir)
{
  strncpy(dir, path, MAX_PATH_SIZE);
  char *slash = strrchr(dir, '/');
  if (slash)
    *slash = '\0';
}

static dir_cache *new_cache(const char *path)
{
  dir_cache *cw = (dir_cache *)calloc(sizeof(dir_cache), 1);
  cw->path = strdup(path);
  cw->prev = NULL;
  cw->entries = NULL;
  cw->cached = time(NULL);
  if (dcache)
    dcache->prev = cw;
  cw->next = dcache;
  return (dcache = cw);
}

int caching_list_directory(const char *path, dir_entry **list)
{
  pthread_mutex_lock(&dmut);
  if (!strcmp(path, "/"))
    path = "";
  dir_cache *cw;
  for (cw = dcache; cw; cw = cw->next)
    if (!strcmp(cw->path, path))
      break;
  if (!cw)
  {
    if (!list_directory(path, list))
      return  0;
    cw = new_cache(path);
  }
  else if (time(NULL) - cw->cached > CACHE_TIMEOUT)
  {
    if (!list_directory(path, list))
      return  0;
    free_dir_list(cw->entries);
    cw->cached = time(NULL);
  }
  else
    *list = cw->entries;
  cw->entries = *list;
  pthread_mutex_unlock(&dmut);
  return 1;
}

static void update_dir_cache(const char *path, int size, int isdir)
{
  pthread_mutex_lock(&dmut);
  dir_cache *cw;
  dir_entry *de;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = dcache; cw; cw = cw->next)
  {
    if (!strcmp(cw->path, dir))
    {
      for (de = cw->entries; de; de = de->next)
      {
        if (!strcmp(de->full_name, path))
        {
          de->size = size;
          pthread_mutex_unlock(&dmut);
          return;
        }
      }
      de = (dir_entry *)malloc(sizeof(dir_entry));
      de->size = size;
      de->isdir = isdir;
      de->name = strdup(&path[strlen(cw->path)+1]);
      de->full_name = strdup(path);
      de->content_type = strdup(isdir ? "application/directory" : "application/octet-stream");
      de->next = cw->entries;
      cw->entries = de;
      if (isdir)
        new_cache(path);
      break;
    }
  }
  pthread_mutex_unlock(&dmut);
}

static void dir_decache(const char *path)
{
  dir_cache *cw;
  pthread_mutex_lock(&dmut);
  dir_entry *de, *tmpde;
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  for (cw = dcache; cw; cw = cw->next)
  {
    if (!strcmp(cw->path, path))
    {
      if (cw == dcache)
        dcache = cw->next;
      if (cw->prev)
        cw->prev->next = cw->next;
      if (cw->next)
        cw->next->prev = cw->prev;
      free_dir_list(cw->entries);
      free(cw->path);
      free(cw);
    }
    else if (cw->entries && !strcmp(dir, cw->path))
    {
      if (!strcmp(cw->entries->full_name, path))
      {
        de = cw->entries;
        cw->entries = de->next;
        de->next = NULL;
        free_dir_list(de);
      }
      else for (de = cw->entries; de->next; de = de->next)
      {
        if (!strcmp(de->next->full_name, path))
        {
          tmpde = de->next;
          de->next = de->next->next;
          tmpde->next = NULL;
          free_dir_list(tmpde);
          break;
        }
      }
    }
  }
  pthread_mutex_unlock(&dmut);
}

static dir_entry *path_info(const char *path)
{
  char dir[MAX_PATH_SIZE];
  dir_for(path, dir);
  dir_entry *tmp;
  if (!caching_list_directory(dir, &tmp))
    return NULL;
  for (; tmp; tmp = tmp->next)
  {
    if (!strcmp(tmp->full_name, path))
      return tmp;
  }
  return NULL;
}

static int cfs_getattr(const char *path, struct stat *stbuf)
{
  if (!strcmp(path, "/"))
  {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    return 0;
  }
  dir_entry *de = path_info(path);
  if (!de)
    return -ENOENT;
  stbuf->st_mtime = de->last_modified;
  if (de->isdir)
  {
    stbuf->st_size = 0;
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
  }
  else
  {
    stbuf->st_size = de->size;
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
  }
  return 0;
}

static int cfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *info)
{
  if (info->fh)
  {
    stbuf->st_size = file_size(info->fh);
    stbuf->st_mode = S_IFREG | 0444;
    stbuf->st_nlink = 1;
    return 0;
  }
  return -ENOENT;
}

static int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *info)
{
  dir_entry *de;
  if (!caching_list_directory(path, &de))
    return -ENOLINK;
  filldir(buf, ".", NULL, 0);
  filldir(buf, "..", NULL, 0);
  for (; de; de = de->next)
    filldir(buf, de->name, NULL, 0);
  return 0;
}

static int cfs_mkdir(const char *path, mode_t mode)
{
  if (create_directory(path))
  {
    update_dir_cache(path, 0, 1);
    return 0;
  }
  return -ENOENT;
}

static int cfs_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
  FILE *temp_file = tmpfile();
  info->fh = dup(fileno(temp_file));
  update_dir_cache(path, 0, 0);
  fclose(temp_file);
  info->direct_io = 1;
  return 0;
}

static int cfs_open(const char *path, struct fuse_file_info *info)
{
  cfs_create(path, info->flags, info);
  FILE *tmp = fdopen(dup(info->fh), "w");
  object_write_to(path, tmp);
  fclose(tmp);
  return 0;
}

static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
  lseek(info->fh, offset, SEEK_SET);
  return read(info->fh, buf, size);
}

static int cfs_release(const char *path, struct fuse_file_info *info)
{
  update_dir_cache(path, file_size(info->fh), 0);
  if (info->flags & O_RDWR || info->flags & O_WRONLY)
  {
    FILE *fp = fdopen(info->fh, "r");
    fseek(fp, 0, SEEK_SET);
    if (!object_read_from(path, fp))
    {
      fclose(fp);
      return -ENOENT;
    }
    fclose(fp);
  }
  else
    close(info->fh);
  return 0;
}

static int cfs_rmdir(const char *path)
{
  if (delete_object(path))
  {
    dir_decache(path);
    return 0;
  }
  return -ENOENT;
}

static int cfs_ftruncate(const char *path, off_t size, struct fuse_file_info *info)
{
  ftruncate(info->fh, size);
  lseek(info->fh, 0, SEEK_SET);
  update_dir_cache(path, size, 0);
  return 0;
}

static int cfs_write(const char *path, const char *buf, size_t length, off_t offset, struct fuse_file_info *info)
{
  lseek(info->fh, offset, SEEK_SET);
  update_dir_cache(path, offset + length, 0);
  return write(info->fh, buf, length);
}

static int cfs_unlink(const char *path)
{
  if (delete_object(path))
  {
    dir_decache(path);
    return 0;
  }
  return -ENOENT;
}

static int cfs_fsync(const char *path, int idunno, struct fuse_file_info *info)
{
  return 0;
}

static int cfs_truncate(const char *path, off_t size)
{
  object_truncate(path);
  return 0;
}

int main(int argc, char **argv)
{
  char username[1024] = "", api_key[1024] = "";
  char *home, settings_filename[1024];
  FILE *settings;
  struct fuse_operations cfs_oper;

  if ((home = getenv("HOME")))
  {
    snprintf(settings_filename, sizeof(settings_filename), "%s/.cloudfuse", home);
    if ((settings = fopen(settings_filename, "r")))
    {
      char line[1024];
      while (fgets(line, sizeof(line), settings))
      {
        sscanf(line, " username = %[^\r\n ]", username);
        sscanf(line, " api_key = %[^\r\n ]", api_key);
      }
      fclose(settings);
    }
  }
  if (!*username || !*api_key)
  {
    fprintf(stderr, "Unable to read %s\n", settings_filename);
    fprintf(stderr, "It should contain:\n\n");
    fprintf(stderr, "  username=[Mosso username]\n");
    fprintf(stderr, "  api_key=[Mosso api key]\n");
    return 1;
  }
  if (!cloudfs_connect(username, api_key))
  {
    fprintf(stderr, "Unable to authenticate.\n");
    return 1;
  }

  memset(&cfs_oper, 0, sizeof(cfs_oper));
  cfs_oper.readdir = cfs_readdir;
  cfs_oper.mkdir = cfs_mkdir;
  cfs_oper.read = cfs_read;
  cfs_oper.create = cfs_create;
  cfs_oper.open = cfs_open;
  cfs_oper.fgetattr = cfs_fgetattr;
  cfs_oper.getattr = cfs_getattr;
  cfs_oper.release = cfs_release;
  cfs_oper.rmdir = cfs_rmdir;
  cfs_oper.ftruncate = cfs_ftruncate;
  cfs_oper.truncate = cfs_truncate;
  cfs_oper.write = cfs_write;
  cfs_oper.unlink = cfs_unlink;
  cfs_oper.fsync = cfs_fsync;

  pthread_mutexattr_init(&dmattr);
  pthread_mutex_init(&dmut, &dmattr);

  return fuse_main(argc, argv, &cfs_oper, NULL);
}

