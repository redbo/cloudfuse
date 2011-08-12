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

struct options {
    char username[OPTION_SIZE];
    char api_key[OPTION_SIZE];
    char cache_timeout[OPTION_SIZE];
    char authurl[OPTION_SIZE];
    char use_snet[OPTION_SIZE];
} options = {
    .username = "",
    .api_key = "",
    .cache_timeout = "600",
    .authurl = "https://auth.api.rackspacecloud.com/v1.0",
    .use_snet = "false",
};

