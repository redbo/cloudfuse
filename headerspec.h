#ifndef _HEADERSPEC_H
#define _HEADERSPEC_H

#include <curl/curl.h>

typedef struct match_spec {
  char *pattern;
  int is_positive;
  char *header_value;
  struct match_spec *next;
} match_spec;

typedef struct header_spec {
  char *header_key;
  match_spec *matches;
  struct header_spec *next;
} header_spec;

int parse_spec(const char *spec, header_spec **output);

int add_matching_headers(void (add_header_func)(struct curl_slist **headers, const char *name, const char *value),
			 struct curl_slist **headers, header_spec *spec, const char *path);

void free_spec(header_spec *spec);

#endif // _HEADERSPEC_H
