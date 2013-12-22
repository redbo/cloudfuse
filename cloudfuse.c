#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include "cloudfsapi.h"
#include "config.h"


#define OPTION_SIZE 1024

static int cache_timeout;

typedef struct dir_cache
{
  char *path;
  dir_entry *entries;
  time_t cached;
  struct dir_cache *next, *prev;
} dir_cache;
static dir_cache *dcache;
static pthread_mutex_t dmut;

typedef struct
{
  int fd;
  int flags;
} openfile;


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

static int caching_list_directory(const char *path, dir_entry **list)
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
    if (!cloudfs_list_directory(path, list))
      return  0;
    cw = new_cache(path);
  }
  else if (cache_timeout > 0 && (time(NULL) - cw->cached > cache_timeout))
  {
    if (!cloudfs_list_directory(path, list))
      return  0;
    cloudfs_free_dir_list(cw->entries);
    cw->cached = time(NULL);
  }
  else
    *list = cw->entries;
  cw->entries = *list;
  pthread_mutex_unlock(&dmut);
  return 1;
}

static void update_dir_cache(const char *path, off_t size, int isdir, int islink)
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
      de->islink = islink;
      de->name = strdup(&path[strlen(cw->path)+1]);
      de->full_name = strdup(path);

      if (isdir)
      {
        de->content_type = strdup("application/link");
      }
      if(islink)
      {
        de->content_type = strdup("application/directory");
      }
      else
      {

        de->content_type = strdup("application/octet-stream");
      }
      de->last_modified = time(NULL);
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
      cloudfs_free_dir_list(cw->entries);
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
        cloudfs_free_dir_list(de);
      }
      else for (de = cw->entries; de->next; de = de->next)
      {
        if (!strcmp(de->next->full_name, path))
        {
          tmpde = de->next;
          de->next = de->next->next;
          tmpde->next = NULL;
          cloudfs_free_dir_list(tmpde);
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
  stbuf->st_uid = geteuid();
  stbuf->st_gid = getegid();
  if (!strcmp(path, "/"))
  {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    return 0;
  }
  dir_entry *de = path_info(path);
  if (!de)
    return -ENOENT;
  stbuf->st_ctime = stbuf->st_mtime = de->last_modified;
  if (de->isdir)
  {
    stbuf->st_size = 0;
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
  }
  else if (de->islink)
  {
    stbuf->st_size = 1;
    stbuf->st_mode = S_IFLNK | 0755;
    stbuf->st_nlink = 1;
    stbuf->st_size = de->size;
    /* calc. blocks as if 4K blocksize filesystem; stat uses units of 512B */
    stbuf->st_blocks = ((4095 + de->size) / 4096) * 8;
  }
  else
  {
    stbuf->st_size = de->size;
    /* calc. blocks as if 4K blocksize filesystem; stat uses units of 512B */
    stbuf->st_blocks = ((4095 + de->size) / 4096) * 8;
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
  }
  return 0;
}

static int cfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *info)
{
  openfile *of = (openfile *)(uintptr_t)info->fh;
  if (of)
  {
    stbuf->st_size = cloudfs_file_size(of->fd);
    stbuf->st_mode = S_IFREG | 0666;
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
  if (cloudfs_create_directory(path))
  {
    update_dir_cache(path, 0, 1, 0);
    return 0;
  }
  return -ENOENT;
}

static int cfs_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
  FILE *temp_file = tmpfile();
  openfile *of = (openfile *)malloc(sizeof(openfile));
  of->fd = dup(fileno(temp_file));
  fclose(temp_file);
  of->flags = info->flags;
  info->fh = (uintptr_t)of;
  update_dir_cache(path, 0, 0, 0);
  info->direct_io = 1;
  return 0;
}

static int cfs_open(const char *path, struct fuse_file_info *info)
{
  FILE *temp_file = tmpfile();
  dir_entry *de = path_info(path);
  if (!(info->flags & O_WRONLY))
  {
    if (!cloudfs_object_write_fp(path, temp_file))
    {
      fclose(temp_file);
      return -ENOENT;
    }
    update_dir_cache(path, (de ? de->size : 0), 0, 0);
  }
  openfile *of = (openfile *)malloc(sizeof(openfile));
  of->fd = dup(fileno(temp_file));
  fclose(temp_file);
  of->flags = info->flags;
  info->fh = (uintptr_t)of;
  info->direct_io = 1;
  return 0;
}

static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
  return pread(((openfile *)(uintptr_t)info->fh)->fd, buf, size, offset);
}

static int cfs_flush(const char *path, struct fuse_file_info *info)
{
  openfile *of = (openfile *)(uintptr_t)info->fh;
  if (of)
  {
    update_dir_cache(path, cloudfs_file_size(of->fd), 0, 0);
    if (of->flags & O_RDWR || of->flags & O_WRONLY)
    {
      FILE *fp = fdopen(dup(of->fd), "r");
      rewind(fp);
      if (!cloudfs_object_read_fp(path, fp))
      {
        fclose(fp);
        return -ENOENT;
      }
      fclose(fp);
    }
  }
  return 0;
}

static int cfs_release(const char *path, struct fuse_file_info *info)
{
  close(((openfile *)(uintptr_t)info->fh)->fd);
  return 0;
}

static int cfs_rmdir(const char *path)
{
  if (cloudfs_delete_object(path))
  {
    dir_decache(path);
    return 0;
  }
  return -ENOENT;
}

static int cfs_ftruncate(const char *path, off_t size, struct fuse_file_info *info)
{
  openfile *of = (openfile *)(uintptr_t)info->fh;
  if (ftruncate(of->fd, size))
    return -errno;
  lseek(of->fd, 0, SEEK_SET);
  update_dir_cache(path, size, 0, 0);
  return 0;
}

static int cfs_write(const char *path, const char *buf, size_t length, off_t offset, struct fuse_file_info *info)
{
  update_dir_cache(path, offset + length, 0, 0);
  return pwrite(((openfile *)(uintptr_t)info->fh)->fd, buf, length, offset);
}

static int cfs_unlink(const char *path)
{
  if (cloudfs_delete_object(path))
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
  cloudfs_object_truncate(path, size);
  return 0;
}

static int cfs_statfs(const char *path, struct statvfs *stat)
{
  stat->f_bsize = 4096;
  stat->f_frsize = 4096;
  stat->f_blocks = INT_MAX;
  stat->f_bfree = stat->f_blocks;
  stat->f_bavail = stat->f_blocks;
  stat->f_files = INT_MAX;
  stat->f_ffree = INT_MAX;
  stat->f_favail = INT_MAX;
  stat->f_namemax = INT_MAX;
  return 0;
}

static int cfs_chown(const char *path, uid_t uid, gid_t gid)
{
  return 0;
}

static int cfs_chmod(const char *path, mode_t mode)
{
  return 0;
}

static int cfs_rename(const char *src, const char *dst)
{
  dir_entry *src_de = path_info(src);
  if (!src_de)
      return -ENOENT;
  if (src_de->isdir)
    return -EISDIR;
  if (cloudfs_copy_object(src, dst))
  {
    /* FIXME this isn't quite right as doesn't preserve last modified */
    update_dir_cache(dst, src_de->size, 0, 0);
    return cfs_unlink(src);
  }
  return -EIO;
}

static int cfs_symlink(const char *src, const char *dst)
{
  if(cloudfs_create_symlink(src, dst))
  {
    update_dir_cache(dst, 1, 0, 1);
    return 0;
  }
  return -EIO;
}

static int cfs_readlink(const char* path, char* buf, size_t size)
{
  FILE *temp_file = tmpfile();
  int ret = 0;

  if (!cloudfs_object_write_fp(path, temp_file))
  {
      ret = -ENOENT;
  }

  if (!pread(fileno(temp_file), buf, size, 0))
  {
      ret = -ENOENT;
  }

  fclose(temp_file);
  return ret;
}

static void *cfs_init(struct fuse_conn_info *conn)
{
  signal(SIGPIPE, SIG_IGN);
  return NULL;
}

char *get_home_dir()
{
  char *home;
  if ((home = getenv("HOME")) && !access(home, R_OK))
    return home;
  struct passwd *pwd = getpwuid(geteuid());
  if ((home = pwd->pw_dir) && !access(home, R_OK))
    return home;
  return "~";
}

static struct options {
    char username[OPTION_SIZE];
    char tenant[OPTION_SIZE];
    char password[OPTION_SIZE];
    char cache_timeout[OPTION_SIZE];
    char authurl[OPTION_SIZE];
    char region[OPTION_SIZE];
    char use_snet[OPTION_SIZE];
    char verify_ssl[OPTION_SIZE];
} options = {
    .username = "",
    .password = "",
    .tenant = "",
    .cache_timeout = "600",
    .authurl = "https://identity.api.rackspacecloud.com/v2.0/",
    .region = "",
    .use_snet = "false",
    .verify_ssl = "true",
};

int parse_option(void *data, const char *arg, int key, struct fuse_args *outargs)
{
  if (sscanf(arg, " username = %[^\r\n ]", options.username) ||
      sscanf(arg, " tenant = %[^\r\n ]", options.tenant) ||
      sscanf(arg, " api_key = %[^\r\n ]", options.password) ||
      sscanf(arg, " password = %[^\r\n ]", options.password) ||
      sscanf(arg, " cache_timeout = %[^\r\n ]", options.cache_timeout) ||
      sscanf(arg, " authurl = %[^\r\n ]", options.authurl) ||
      sscanf(arg, " region = %[^\r\n ]", options.region) ||
      sscanf(arg, " use_snet = %[^\r\n ]", options.use_snet) ||
      sscanf(arg, " verify_ssl = %[^\r\n ]", options.verify_ssl))
    return 0;
  if (!strcmp(arg, "-f") || !strcmp(arg, "-d") || !strcmp(arg, "debug"))
    cloudfs_debug(1);
  return 1;
}

int main(int argc, char **argv)
{
  char settings_filename[MAX_PATH_SIZE] = "";
  FILE *settings;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  snprintf(settings_filename, sizeof(settings_filename), "%s/.cloudfuse", get_home_dir());
  if ((settings = fopen(settings_filename, "r")))
  {
    char line[OPTION_SIZE];
    while (fgets(line, sizeof(line), settings))
      parse_option(NULL, line, -1, &args);
    fclose(settings);
  }

  fuse_opt_parse(&args, &options, NULL, parse_option);

  cache_timeout = atoi(options.cache_timeout);

  if (!*options.username || !*options.password)
  {
    fprintf(stderr, "Unable to determine username and API key.\n\n");
    fprintf(stderr, "These can be set either as mount options or in"
                    "a file named %s\n\n", settings_filename);
    fprintf(stderr, "  username=[Account username]\n");
    fprintf(stderr, "  api_key=[API key (or password for Keystone API)]\n\n");
    fprintf(stderr, "The following settings are optional:\n\n");
    fprintf(stderr, "  authurl=[Authentication url - connect to non-Rackspace Swift]\n");
    fprintf(stderr, "  tenant=[Tenant for authentication with Keystone]\n");
    fprintf(stderr, "  password=[Password for authentication with Keystone]\n");
    fprintf(stderr, "  use_snet=[True to use Rackspace ServiceNet for connections]\n");
    fprintf(stderr, "  cache_timeout=[Seconds for directory caching, default 600]\n");
    fprintf(stderr, "  verify_ssl=[False to disable SSL cert verification]\n");

    return 1;
  }

  cloudfs_init();

  cloudfs_verify_ssl(!strcasecmp(options.verify_ssl, "true"));

  cloudfs_set_credentials(options.username, options.tenant, options.password,
                          options.authurl, options.region,
                          !strcasecmp(options.use_snet, "true"));
  if (!cloudfs_connect())
  {
    fprintf(stderr, "Failed to authenticate.\n");
    return 1;
  }

  #ifndef HAVE_OPENSSL
  #warning Compiling without libssl, will run single-threaded.
  fuse_opt_add_arg(&args, "-s");
  #endif

  struct fuse_operations cfs_oper = {
    .readdir = cfs_readdir,
    .mkdir = cfs_mkdir,
    .read = cfs_read,
    .create = cfs_create,
    .open = cfs_open,
    .fgetattr = cfs_fgetattr,
    .getattr = cfs_getattr,
    .flush = cfs_flush,
    .release = cfs_release,
    .rmdir = cfs_rmdir,
    .ftruncate = cfs_ftruncate,
    .truncate = cfs_truncate,
    .write = cfs_write,
    .unlink = cfs_unlink,
    .fsync = cfs_fsync,
    .statfs = cfs_statfs,
    .chmod = cfs_chmod,
    .chown = cfs_chown,
    .rename = cfs_rename,
    .symlink = cfs_symlink,
    .readlink = cfs_readlink,
    .init = cfs_init,
  };

  pthread_mutex_init(&dmut, NULL);
  return fuse_main(args.argc, args.argv, &cfs_oper, &options);
}

