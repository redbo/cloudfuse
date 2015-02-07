#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include "headerspec.h"

static int next_token(const char *spec /* in */, int *scanstart /* in/out */,
		      int *tokenstart /* out */, int *tokenlen /* out */) {

  const char *start = spec + *scanstart;
  const char *thisc = start;

  // skip any leading whitespace
  while(*thisc==' ' || *thisc=='\t' || *thisc=='\n' || *thisc=='\r') {
    thisc++;
  }

  // detect end of input
  if(!*thisc) return 0;

  // Handle quote
  if(*thisc=='"') {
    thisc++;
    *tokenstart = thisc - spec;
    while(1) {
      if(*thisc == '"') {
	*tokenlen = (thisc - spec) - *tokenstart;
	*scanstart = *tokenstart + *tokenlen + 1; // trim trailing "
	return 1;
      } else if(*thisc == 0) { // Handle unterminated string
	*tokenlen = (thisc - spec) - *tokenstart;
	*scanstart = *tokenstart + *tokenlen;
	return 0;
      }
      thisc++;
    }
  } else if(*thisc==':') {
    *tokenstart = thisc - spec;
    *tokenlen = 1;
    *scanstart = *tokenstart + *tokenlen;
    return 1;
  } else if(*thisc==';') {
    *tokenstart = thisc - spec;
    *tokenlen = 1;
    *scanstart = *tokenstart + *tokenlen;
    return 1;
  } else if(*thisc==',') {
    *tokenstart = thisc - spec;
    *tokenlen = 1;
    *scanstart = *tokenstart + *tokenlen;
    return 1;
  } else if(*thisc=='!') {
    *tokenstart = thisc - spec;
    *tokenlen = 1;
    *scanstart = *tokenstart + *tokenlen;
    return 1;
  } else { // An actual token
    *tokenstart = thisc - spec;

    while(1) {
      thisc++;
      if(*thisc==' ' || *thisc=='\t' || *thisc=='\n' || *thisc=='\r' || *thisc=='"'
	 || *thisc==':' || *thisc==';' || *thisc==',' || *thisc=='!' || *thisc==0) break;
    }
    
    *tokenlen = (thisc - spec) - *tokenstart;
    *scanstart = *tokenstart + *tokenlen;

    return 1;
  }
}

static enum {
  EXPECT_EOF_OR_SEMI_OR_HEADERKEY,
  EXPECT_COLON,
  EXPECT_NEGATE_OR_MATCH,
  EXPECT_MATCH,
  EXPECT_HEADER_VALUE,
  EXPECT_EOF_OR_COMMA_OR_SEMI
} parse_states;

int parse_spec(const char *spec, header_spec **output) {

  printf("Entire spec is %s\n",spec);

  int scanstart = 0;
  int tokenstart, tokenlen;

  int state = EXPECT_EOF_OR_SEMI_OR_HEADERKEY;
  while(next_token(spec,&scanstart,&tokenstart,&tokenlen)) {
    printf("Found token at %d len %d\n",tokenstart,tokenlen);

    char fc = *(spec+tokenstart); // first char of token

    char *headerkey, *pattern, *headervalue;
    int isnegated;
    header_spec *speclist_tail;

    switch(state) {
    case EXPECT_EOF_OR_SEMI_OR_HEADERKEY:
      if(';' == fc) continue;
      if(':'==fc || '!'==fc || ','==fc) {
	printf("In state %d, encountered unexpected token at %d len %d\n",state,tokenstart,tokenlen);
	return 0;
      }
      headerkey = strndup(spec+tokenstart,tokenlen);
      printf("Header key is %s\n",headerkey);

      // Create a new tail for the linked list.
      speclist_tail = *output;
      if(speclist_tail) {
	while(speclist_tail->next) {
	  speclist_tail = speclist_tail->next;
	}
	speclist_tail->next = malloc(sizeof(header_spec));
	speclist_tail = speclist_tail->next;
      } else { // special case for first list element
	*output = malloc(sizeof(header_spec));
	speclist_tail = *output;
      }

      printf("Allocated speclist\n");
      speclist_tail->header_key = headerkey;
      speclist_tail->matches = NULL;
      speclist_tail->next = NULL;

      state = EXPECT_COLON;
      break;
    case EXPECT_COLON:
      if(':'!=fc) {
	printf("In state %d, encountered unexpected token at %d len %d\n",state,tokenstart,tokenlen);
	return 0;
      }
      state = EXPECT_NEGATE_OR_MATCH;
      break;
    case EXPECT_NEGATE_OR_MATCH:
      isnegated = 0;
      if('!'==fc) {
	printf("Match is negated\n");
	isnegated = 1;
	state = EXPECT_MATCH;
      } else if(':'==fc || ','==fc || ';'==fc) {
	printf("In state %d, encountered unexpected token at %d len %d\n",state,tokenstart,tokenlen);
	return 0;
      } else {
	pattern = strndup(spec+tokenstart,tokenlen);
	printf("Pattern is %s\n",pattern);
	state = EXPECT_HEADER_VALUE;
      }
      break;
    case EXPECT_MATCH:
      if(':'==fc || '!'==fc || ','==fc || ';'==fc) {
	printf("In state %d, encountered unexpected token at %d len %d\n",state,tokenstart,tokenlen);
	return 0;
      }
      pattern = strndup(spec+tokenstart,tokenlen);
      printf("Pattern is %s\n",pattern);
      state = EXPECT_HEADER_VALUE;
      break;
    case EXPECT_HEADER_VALUE:
      if(':'==fc || '!'==fc || ','==fc || ';'==fc) {
	printf("In state %d, encountered unexpected token at %d len %d\n",state,tokenstart,tokenlen);
	return 0;
      }
      headervalue = strndup(spec+tokenstart,tokenlen);
      printf("Header value is %s\n",headervalue);

      match_spec *matchlist_tail;
      if(speclist_tail->matches) {
	matchlist_tail = speclist_tail->matches;
	while(matchlist_tail->next) {
	  matchlist_tail = matchlist_tail->next;
	}
	matchlist_tail->next = malloc(sizeof(match_spec));
	matchlist_tail = matchlist_tail->next;
      } else {
	matchlist_tail = malloc(sizeof(match_spec));
	speclist_tail->matches = matchlist_tail;
      }

      matchlist_tail->next = NULL;
      matchlist_tail->pattern = pattern;
      matchlist_tail->is_positive = !isnegated;
      matchlist_tail->header_value = headervalue;

      state = EXPECT_EOF_OR_COMMA_OR_SEMI;
      break;
    case EXPECT_EOF_OR_COMMA_OR_SEMI:
      if(','==fc) {
	state=EXPECT_NEGATE_OR_MATCH;
      } else if(';'==fc) {
	state=EXPECT_EOF_OR_SEMI_OR_HEADERKEY;
      } else {
	printf("In state %d, encountered unexpected token at %d len %d\n",state,tokenstart,tokenlen);
	return 0;
      }
      break;
    default:
      printf("In unexpected state %d with token at %d len %d\n",state,tokenstart,tokenlen);
      return 0;
    }
  }

  if(state != EXPECT_EOF_OR_SEMI_OR_HEADERKEY && state != EXPECT_EOF_OR_COMMA_OR_SEMI) {
    printf("Finished parse in unexpected state %d\n",state);
    return 0;
  }

  printf("Parse completed successfully\n");
  return 1;
}

void free_spec(header_spec *spec) {
  if(!spec) return;

  /* printf("Freeing spec at %p\n",spec); */
  free(spec->header_key);

  // free matches;
  match_spec *onematch = spec->matches;
  while(onematch) {
    /* printf("Freeing match with value %s\n",onematch->header_value); */
    free(onematch->pattern);
    free(onematch->header_value);
    match_spec *nextmatch = onematch->next;
    free(onematch);
    onematch = nextmatch;
  }

  header_spec *next = spec->next;
  free(spec);
  free_spec(next);
}

int add_matching_headers(void (add_header_func)(struct curl_slist **headers, const char *name, const char *value),
			 struct curl_slist **headers, header_spec *spec, const char *path) {

  header_spec *onespec = spec;
  while(onespec) {

    printf("Testing one spec\n");
    match_spec *onematch = onespec->matches;
    while(onematch) {

      int result = fnmatch(onematch->pattern,path,0);
      printf("Testing one match, path being %s, result was %d\n",path,result);
      if(!result) {
	add_header_func(headers,onespec->header_key,onematch->header_value);
	break;
      }
      onematch = onematch->next;
    }

    onespec = onespec->next;
  }

}
