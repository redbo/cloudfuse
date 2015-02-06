#include <stdio.h>
#include <stdlib.h>
#include "../headerspec.h"
#include "../cloudfsapi.h"

int main(int argc, char **argv) {
  if(argc != 3) {
    printf("Usage: %s <specscript> <path>\n", argv[0]);
    exit(1);
  }

  char *spec = argv[1];
  char *path = argv[2];

  header_spec *parsed = NULL;
  parse_spec(spec, &parsed);

  if(parsed) printf("parsed has been assigned\n");

  struct curl_slist *headers = NULL; //malloc(sizeof(struct curl_slist));
  add_matching_headers(add_header,&headers,parsed,path);

  struct curl_slist *onestr = headers;
  while(onestr) {
    printf("Header is %s\n",onestr->data);
    onestr = onestr->next;
  }

  free_spec(parsed);
  return 0;
}
