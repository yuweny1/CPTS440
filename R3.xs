#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "const-c.inc"

//#define PERL_R3_DEBUG

/* __R3_SOURCE_SLOT_BEGIN__ */
#define HAVE_STRNDUP
#define HAVE_STRDUP
/******* r3/3rdparty/zmalloc.h *******/
#ifndef ZMALLOC_H
#define ZMALLOC_H

/* zmalloc - total amount of allocated memory aware version of malloc()
 *
 * Copyright (c) 2009-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Double expansion needed for stringification of macro values. */
#define __xstr(s) __str(s)
#define __str(s) #s

#if defined(USE_TCMALLOC)
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))
#include <google/tcmalloc.h>
#if (TC_VERSION_MAJOR == 1 && TC_VERSION_MINOR >= 6) || (TC_VERSION_MAJOR > 1)
#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) tc_malloc_size(p)
#else
#error "Newer version of tcmalloc required"
#endif

#elif defined(USE_JEMALLOC) && (JEMALLOC_VERSION_MAJOR > 2)
#define ZMALLOC_LIB ("jemalloc-" __xstr(JEMALLOC_VERSION_MAJOR) "." __xstr(JEMALLOC_VERSION_MINOR) "." __xstr(JEMALLOC_VERSION_BUGFIX))
#include <jemalloc/jemalloc.h>
#if (JEMALLOC_VERSION_MAJOR == 2 && JEMALLOC_VERSION_MINOR >= 1) || (JEMALLOC_VERSION_MAJOR > 2)
#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) je_malloc_usable_size(p)
#else
#error "Newer version of jemalloc required"
#endif

#elif defined(__APPLE__)
#include <malloc/malloc.h>
#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) malloc_size(p)
#endif

#ifndef ZMALLOC_LIB
#define ZMALLOC_LIB "libc"
#endif

void *zmalloc(size_t size);
void *zcalloc(size_t size);
void *zrealloc(void *ptr, size_t size);
void zfree(void *ptr);
char *zstrdup(const char *s);
char *zstrndup(const char *s, size_t n);
size_t zmalloc_used_memory(void);
void zmalloc_enable_thread_safeness(void);
void zmalloc_set_oom_handler(void (*oom_handler)(size_t));
float zmalloc_get_fragmentation_ratio(size_t rss);
size_t zmalloc_get_rss(void);
size_t zmalloc_get_private_dirty(void);
void zlibc_free(void *ptr);

#ifndef HAVE_MALLOC_SIZE
size_t zmalloc_size(void *ptr);
#endif

#endif // ZMALLOC_H
/******* r3/include/r3_define.h *******/
/*
 * r3_define.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef DEFINE_H
#define DEFINE_H
#include <stdbool.h>

#ifndef bool
typedef unsigned char bool;
#endif
#ifndef FALSE
#    define FALSE 0
#endif
#ifndef TRUE
#    define TRUE 1
#endif

// #define DEBUG 1
#ifdef DEBUG

#define info(fmt, ...) \
            do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define debug(fmt, ...) \
        do { fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)

#else
#define info(...);
#define debug(...);
#endif

#endif /* !DEFINE_H */
/******* r3/include/str_array.h *******/
/*
 * str_array.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef STR_ARRAY_H
#define STR_ARRAY_H

typedef struct _str_array {
  char **tokens;
  int    len;
  int    cap;
} str_array;

str_array * str_array_create(int cap);

bool str_array_is_full(const str_array * l);

bool str_array_resize(str_array *l, int new_cap);

bool str_array_append(str_array * list, char * token);

void str_array_free(str_array *l);

void str_array_dump(const str_array *l);

str_array * split_route_pattern(char *pattern, int pattern_len);

#define str_array_fetch(t,i)  t->tokens[i]
#define str_array_len(t)  t->len
#define str_array_cap(t)  t->cap

#endif /* !STR_ARRAY_H */
/******* r3/include/match_entry.h *******/
/*
 * match_entry.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef MATCH_ENTRY_H
#define MATCH_ENTRY_H

/* #include "r3_define.h" */
/* #include "str_array.h" */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    str_array * vars;
    const char * path; // current path to dispatch
    int    path_len; // the length of the current path
    int    request_method;  // current request method

    void * data; // route ptr

    char * host; // the request host
    int    host_len;

    char * remote_addr;
    int    remote_addr_len;
} match_entry;

match_entry * match_entry_createl(const char * path, int path_len);

#define match_entry_create(path) match_entry_createl(path,strlen(path))

void match_entry_free(match_entry * entry);

#ifdef __cplusplus
}
#endif

#endif /* !MATCH_ENTRY_H */
/******* r3/include/r3.h *******/
/*
 * r3.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#ifndef R3_NODE_H
#define R3_NODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>
#include <stdbool.h>
/* #include "config.h" */
/* #include "r3_define.h" */
/* #include "str_array.h" */
/* #include "match_entry.h" */

#ifdef ENABLE_JSON
#include <json-c/json.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif

struct _edge;
struct _node;
struct _route;
typedef struct _edge edge;
typedef struct _node node;
typedef struct _route route;

struct _node {
    edge  ** edges;
    // edge  ** edge_table;

    // edges are mostly less than 255
    unsigned char    edge_len;
    unsigned char    compare_type; // compare_type: pcre, opcode, string
    unsigned char    endpoint; // endpoint, should be zero for non-endpoint nodes
    unsigned char    ov_cnt; // capture vector array size for pcre

    // almost less than 255
    unsigned char      edge_cap;
    unsigned char      route_len;
    unsigned char      route_cap;
    // <-- here comes a char[1] struct padding for alignment since we have 4 char above.


    /** compile-time variables here.... **/

    /* the combined regexp pattern string from pattern_tokens */
    pcre * pcre_pattern;
    pcre_extra * pcre_extra;

    route ** routes;

    char * combined_pattern;

    /**
     * the pointer of route data
     */
    void * data;
};

#define node_edge_pattern(node,i) node->edges[i]->pattern
#define node_edge_pattern_len(node,i) node->edges[i]->pattern_len

struct _edge {
    char * pattern;
    node * child;
    unsigned short pattern_len; // 2 byte
    unsigned char  opcode; // 1 byte
    unsigned char  has_slug; // 1 bit
};

struct _route {
    char * path;
    int    path_len;

    int    request_method; // can be (GET || POST)

    char * host; // required host name
    int    host_len;

    void * data;

    char * remote_addr_pattern;
    int    remote_addr_pattern_len;
};


node * r3_tree_create(int cap);

node * r3_node_create();

void r3_tree_free(node * tree);

edge * r3_node_connectl(node * n, const char * pat, int len, int strdup, node *child);

#define r3_node_connect(n, pat, child) r3_node_connectl(n, pat, strlen(pat), 0, child)

edge * r3_node_find_edge(const node * n, const char * pat, int pat_len);

void r3_node_append_edge(node *n, edge *child);


edge * r3_node_find_common_prefix(node *n, char *path, int path_len, int *prefix_len, char **errstr);

node * r3_tree_insert_pathl(node *tree, const char *path, int path_len, void * data);

route * r3_tree_insert_routel(node *tree, int method, const char *path, int path_len, void *data);

#define r3_tree_insert_path(n,p,d) r3_tree_insert_pathl_ex(n,p,strlen(p), NULL, d, NULL)

#define r3_tree_insert_route(n,method,path,data) r3_tree_insert_routel(n, method, path, strlen(path), data)


/**
 * The private API to insert a path
 */
node * r3_tree_insert_pathl_ex(node *tree, const char *path, int path_len, route * route, void * data, char ** errstr);

void r3_tree_dump(const node * n, int level);


edge * r3_node_find_edge_str(const node * n, const char * str, int str_len);


int r3_tree_compile(node *n, char** errstr);

int r3_tree_compile_patterns(node * n, char** errstr);

node * r3_tree_matchl(const node * n, const char * path, int path_len, match_entry * entry);

#define r3_tree_match(n,p,e)  r3_tree_matchl(n,p, strlen(p), e)

// node * r3_tree_match_entry(node * n, match_entry * entry);
#define r3_tree_match_entry(n, entry) r3_tree_matchl(n, entry->path, entry->path_len, entry)

bool r3_node_has_slug_edges(const node *n);

edge * r3_edge_createl(const char * pattern, int pattern_len, node * child);

node * r3_edge_branch(edge *e, int dl);

void r3_edge_free(edge * edge);





route * r3_route_create(const char * path);

route * r3_route_createl(const char * path, int path_len);

int r3_route_cmp(const route *r1, const match_entry *r2);

void r3_node_append_route(node * n, route * route);

void r3_route_free(route * route);

route * r3_tree_match_route(const node *n, match_entry * entry);

#define METHOD_GET 2
#define METHOD_POST 2<<1
#define METHOD_PUT 2<<2
#define METHOD_DELETE 2<<3
#define METHOD_PATCH 2<<4
#define METHOD_HEAD 2<<5
#define METHOD_OPTIONS 2<<6



int r3_pattern_to_opcode(const char * pattern, int pattern_len);

enum { NODE_COMPARE_STR, NODE_COMPARE_PCRE, NODE_COMPARE_OPCODE };

enum { OP_EXPECT_MORE_DIGITS = 1, OP_EXPECT_MORE_WORDS, OP_EXPECT_NOSLASH, OP_EXPECT_NODASH, OP_EXPECT_MORE_ALPHA };

#ifdef ENABLE_JSON
json_object * r3_edge_to_json_object(const edge * e);
json_object * r3_node_to_json_object(const node * n);
json_object * r3_route_to_json_object(const route * r);

const char * r3_node_to_json_string_ext(const node * n, int options);
const char * r3_node_to_json_pretty_string(const node * n);
const char * r3_node_to_json_string(const node * n);
#endif

#ifdef __cplusplus
}
#endif

#endif /* !R3_NODE_H */
/******* r3/include/r3_list.h *******/
/*
 * r3_list.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef R3_LIST_H
#define R3_LIST_H

#include <pthread.h>
 
typedef struct _list_item {
  void *value;
  struct _list_item *prev;
  struct _list_item *next;
} list_item;
 
typedef struct {
  int count;
  list_item *head;
  list_item *tail;
  pthread_mutex_t mutex;
} list;
 
list *list_create();
void list_free(list *l);
 
list_item *list_add_element(list *l, void *ptr);
int list_remove_element(list *l, void *ptr);
void list_each_element(list *l, int (*func)(list_item *));
 


#endif /* !R3_LIST_H */
/******* r3/include/r3_str.h *******/
/*
 * r3_str.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#ifndef STR_H
#define STR_H

/* #include "r3.h" */
/* #include "config.h" */

char * slug_compile(const char * str, int len);

char * slug_find_pattern(const char *s1, int *len);

char * slug_find_placeholder(const char *s1, int *len);

char * inside_slug(const char * needle, int needle_len, char *offset, char **errstr);

char * ltrim_slash(char* str);

void str_repeat(char *s, const char *c, int len);

void print_indent(int level);

#ifndef HAVE_STRDUP
char *strdup(const char *s);
#endif

#ifndef HAVE_STRNDUP
char *strndup(const char *s, int n);
#endif


#endif /* !STR_H */

/******* r3/src/slug.h *******/
/*
 * slug.h
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#ifndef R3_SLUG_H
#define R3_SLUG_H

typedef struct {
    /**
     * source path
     */
    char * path;

    int path_len;

    /**
     * slug start pointer
     */
    char * begin;

    /**
     * slug end pointer
     */
    char * end;

    /**
     * slug length
     */
    int len;

    // slug pattern pointer if we have one
    char * pattern;

    // the length of custom pattern, if the pattern is found.
    int    pattern_len;

} r3_slug_t;


r3_slug_t * r3_slug_new(char * path, int path_len);

int r3_slug_check(r3_slug_t *s);

int r3_slug_parse(r3_slug_t *s, char *needle, int needle_len, char *offset, char **errstr);

char * r3_slug_to_str(const r3_slug_t *s);

void r3_slug_free(r3_slug_t * s);

int slug_count(const char * needle, int len, char **errstr);

static inline int r3_path_contains_slug_char(const char * str) {
    return strchr(str, '{') != NULL ? 1 : 0;
}

#endif /* !SLUG_H */
/******* r3/3rdparty/zmalloc.c *******/
/* zmalloc - total amount of allocated memory aware version of malloc()
 *
 * Copyright (c) 2009-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>

/* This function provide us access to the original libc free(). This is useful
 * for instance to free results obtained by backtrace_symbols(). We need
 * to define this function before including zmalloc.h that may shadow the
 * free implementation if we use jemalloc or another non standard allocator. */
void zlibc_free(void *ptr) {
    free(ptr);
}

#include <string.h>
#include <pthread.h>
/* #include "config.h" */
/* #include "zmalloc.h" */

#ifdef HAVE_MALLOC_SIZE
#define PREFIX_SIZE (0)
#else
#if defined(__sun) || defined(__sparc) || defined(__sparc__)
#define PREFIX_SIZE (sizeof(long long))
#else
#define PREFIX_SIZE (sizeof(size_t))
#endif
#endif

/* Explicitly override malloc/free etc when using tcmalloc. */
#if defined(USE_TCMALLOC)
#define malloc(size) tc_malloc(size)
#define calloc(count,size) tc_calloc(count,size)
#define realloc(ptr,size) tc_realloc(ptr,size)
#define free(ptr) tc_free(ptr)
#elif defined(USE_JEMALLOC) && (JEMALLOC_VERSION_MAJOR > 2)
#include <jemalloc/jemalloc.h>
#define malloc(size) je_malloc(size)
#define calloc(count,size) je_calloc(count,size)
#define realloc(ptr,size) je_realloc(ptr,size)
#define free(ptr) je_free(ptr)
#endif

#ifdef HAVE_ATOMIC
#define update_zmalloc_stat_add(__n) __sync_add_and_fetch(&used_memory, (__n))
#define update_zmalloc_stat_sub(__n) __sync_sub_and_fetch(&used_memory, (__n))
#else
#define update_zmalloc_stat_add(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory += (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)

#define update_zmalloc_stat_sub(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory -= (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)

#endif

#define update_zmalloc_stat_alloc(__n) do { \
    size_t _n = (__n); \
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_add(_n); \
    } else { \
        used_memory += _n; \
    } \
} while(0)

#define update_zmalloc_stat_free(__n) do { \
    size_t _n = (__n); \
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_sub(_n); \
    } else { \
        used_memory -= _n; \
    } \
} while(0)

static size_t used_memory = 0;
static int zmalloc_thread_safe = 0;
pthread_mutex_t used_memory_mutex = PTHREAD_MUTEX_INITIALIZER;

static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n",
        size);
    fflush(stderr);
    abort();
}

static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;

void *zmalloc(size_t size) {
    void *ptr = malloc(size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;
#endif
}

void *zcalloc(size_t size) {
    void *ptr = calloc(1, size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;
#endif
}

void *zrealloc(void *ptr, size_t size) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
#endif
    size_t oldsize;
    void *newptr;

    if (ptr == NULL) return zmalloc(size);
#ifdef HAVE_MALLOC_SIZE
    oldsize = zmalloc_size(ptr);
    newptr = realloc(ptr,size);
    if (!newptr) zmalloc_oom_handler(size);

    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(zmalloc_size(newptr));
    return newptr;
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    newptr = realloc(realptr,size+PREFIX_SIZE);
    if (!newptr) zmalloc_oom_handler(size);

    *((size_t*)newptr) = size;
    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(size);
    return (char*)newptr+PREFIX_SIZE;
#endif
}

/* Provide zmalloc_size() for systems where this function is not provided by
 * malloc itself, given that in that case we store a header with this
 * information as the first bytes of every allocation. */
#ifndef HAVE_MALLOC_SIZE
size_t zmalloc_size(void *ptr) {
    void *realptr = (char*)ptr-PREFIX_SIZE;
    size_t size = *((size_t*)realptr);
    /* Assume at least that all the allocations are padded at sizeof(long) by
     * the underlying allocator. */
    if (size&(sizeof(long)-1)) size += sizeof(long)-(size&(sizeof(long)-1));
    return size+PREFIX_SIZE;
}
#endif

void zfree(void *ptr) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
    size_t oldsize;
#endif

    if (ptr == NULL) return;
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    free(realptr);
#endif
}

char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = zmalloc(l);

    memcpy(p,s,l);
    return p;
}

char * zstrndup (const char *s, size_t n)
{
  char *result;
  size_t len = strlen (s);

  if (n < len)
    len = n;

  result = (char *) zmalloc (len + 1);
  if (!result)
    return 0;

  result[len] = '\0';
  return (char *) memcpy (result, s, len);
}

size_t zmalloc_used_memory(void) {
    size_t um;

    if (zmalloc_thread_safe) {
#ifdef HAVE_ATOMIC
        um = __sync_add_and_fetch(&used_memory, 0);
#else
        pthread_mutex_lock(&used_memory_mutex);
        um = used_memory;
        pthread_mutex_unlock(&used_memory_mutex);
#endif
    }
    else {
        um = used_memory;
    }

    return um;
}

void zmalloc_enable_thread_safeness(void) {
    zmalloc_thread_safe = 1;
}

void zmalloc_set_oom_handler(void (*oom_handler)(size_t)) {
    zmalloc_oom_handler = oom_handler;
}

/* Get the RSS information in an OS-specific way.
 *
 * WARNING: the function zmalloc_get_rss() is not designed to be fast
 * and may not be called in the busy loops where Redis tries to release
 * memory expiring or swapping out objects.
 *
 * For this kind of "fast RSS reporting" usages use instead the
 * function RedisEstimateRSS() that is a much faster (and less precise)
 * version of the function. */

#if defined(HAVE_PROC_STAT)
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

size_t zmalloc_get_rss(void) {
    int page = sysconf(_SC_PAGESIZE);
    size_t rss;
    char buf[4096];
    char filename[256];
    int fd, count;
    char *p, *x;

    snprintf(filename,256,"/proc/%d/stat",getpid());
    if ((fd = open(filename,O_RDONLY)) == -1) return 0;
    if (read(fd,buf,4096) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; /* RSS is the 24th field in /proc/<pid>/stat */
    while(p && count--) {
        p = strchr(p,' ');
        if (p) p++;
    }
    if (!p) return 0;
    x = strchr(p,' ');
    if (!x) return 0;
    *x = '\0';

    rss = strtoll(p,NULL,10);
    rss *= page;
    return rss;
}
#elif defined(HAVE_TASKINFO)
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include <mach/mach_init.h>

size_t zmalloc_get_rss(void) {
    task_t task = MACH_PORT_NULL;
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (task_for_pid(current_task(), getpid(), &task) != KERN_SUCCESS)
        return 0;
    task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);

    return t_info.resident_size;
}
#else
size_t zmalloc_get_rss(void) {
    /* If we can't get the RSS in an OS-specific way for this system just
     * return the memory usage we estimated in zmalloc()..
     *
     * Fragmentation will appear to be always 1 (no fragmentation)
     * of course... */
    return zmalloc_used_memory();
}
#endif

/* Fragmentation = RSS / allocated-bytes */
float zmalloc_get_fragmentation_ratio(size_t rss) {
    return (float)rss/zmalloc_used_memory();
}

#if defined(HAVE_PROC_SMAPS)
size_t zmalloc_get_private_dirty(void) {
    char line[1024];
    size_t pd = 0;
    FILE *fp = fopen("/proc/self/smaps","r");

    if (!fp) return 0;
    while(fgets(line,sizeof(line),fp) != NULL) {
        if (strncmp(line,"Private_Dirty:",14) == 0) {
            char *p = strchr(line,'k');
            if (p) {
                *p = '\0';
                pd += strtol(line+14,NULL,10) * 1024;
            }
        }
    }
    fclose(fp);
    return pd;
}
#else
size_t zmalloc_get_private_dirty(void) {
    return 0;
}
#endif
/******* r3/src/match_entry.c *******/
/*
 * match_entry.c
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>
#include <assert.h>
#include <stdbool.h>

/* #include "r3.h" */
/* #include "zmalloc.h" */
/* #include "match_entry.h" */


match_entry * match_entry_createl(const char * path, int path_len) {
    match_entry * entry = zmalloc(sizeof(match_entry));
    if(!entry)
        return NULL;
    entry->vars = str_array_create(3);
    entry->path = path;
    entry->path_len = path_len;
    entry->data = NULL;
    return entry;
}

void match_entry_free(match_entry * entry) {
    assert(entry);
    if (entry->vars) {
        str_array_free(entry->vars);
    }
    zfree(entry);
}
/******* r3/src/edge.c *******/
/*
 * edge.c
 * Copyright (C) 2014 c9s <c9s@c9smba.local>
 *
 * Distributed under terms of the MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Jemalloc memory management
// #include <jemalloc/jemalloc.h>

// PCRE
#include <pcre.h>

// Judy array
// #include <Judy.h>
#include <config.h>

/* #include "r3.h" */
/* #include "r3_str.h" */
/* #include "slug.h" */
/* #include "zmalloc.h" */

edge * r3_edge_createl(const char * pattern, int pattern_len, node * child) {
    edge * e = (edge*) zmalloc( sizeof(edge) );
    e->pattern = (char*) pattern;
    e->pattern_len = pattern_len;
    e->opcode = 0;
    e->child = child;
    e->has_slug = r3_path_contains_slug_char(e->pattern);
    return e;
}



/**
 * branch the edge pattern at "dl" offset,
 * insert a dummy child between the edges.
 *
 *
 * A -> [prefix..suffix] -> B
 * A -> [prefix] -> B -> [suffix] -> New Child (Copy Data, Edges from B)
 *
 */
node * r3_edge_branch(edge *e, int dl) {
    node *new_child;
    edge *e1;
    char * s1 = e->pattern + dl;
    int s1_len = 0;

    // the suffix edge of the leaf
    new_child = r3_tree_create(3);
    s1_len = e->pattern_len - dl;
    e1 = r3_edge_createl(zstrndup(s1, s1_len), s1_len, new_child);

    // Migrate the child edges to the new edge we just created.
    for ( int i = 0 ; i < e->child->edge_len ; i++ ) {
        r3_node_append_edge(new_child, e->child->edges[i]);
        e->child->edges[i] = NULL;
    }
    e->child->edge_len = 0;


    // Migrate the child routes
    for ( int i = 0 ; i < e->child->route_len ; i++ ) {
        r3_node_append_route(new_child, e->child->routes[i]);
        e->child->routes[i] = NULL;
    }
    e->child->route_len = 0;

    // Migrate the endpoint
    new_child->endpoint = e->child->endpoint;
    e->child->endpoint = 0; // reset endpoint

    // Migrate the data
    new_child->data = e->child->data; // copy data pointer
    e->child->data = NULL;

    r3_node_append_edge(e->child, e1);

    // truncate the original edge pattern
    char *oldpattern = e->pattern;
    e->pattern = zstrndup(e->pattern, dl);
    e->pattern_len = dl;
    zfree(oldpattern);

    return new_child;
}

void r3_edge_free(edge * e) {
    zfree(e->pattern);
    if ( e->child ) {
        r3_tree_free(e->child);
    }
    // free itself
    zfree(e);
}

/******* r3/src/list.c *******/
/*
 * list.c Copyright (C) 2014 c9s <c9s@c9smba.local>
 * 
 * Distributed under terms of the MIT license.
 */
#include <stdlib.h>
/* #include "r3_list.h" */
/* #include "zmalloc.h" */

/* Naive linked list implementation */

list           *
list_create()
{
    list           *l = (list *) zmalloc(sizeof(list));
    l->count = 0;
    l->head = NULL;
    l->tail = NULL;
    pthread_mutex_init(&(l->mutex), NULL);
    return l;
}

void
list_free(l)
    list           *l;
{
    if (l) {
        list_item      *li, *tmp;

        pthread_mutex_lock(&(l->mutex));

        if (l != NULL) {
            li = l->head;
            while (li != NULL) {
                tmp = li->next;
                li = tmp;
            }
        }
        pthread_mutex_unlock(&(l->mutex));
        pthread_mutex_destroy(&(l->mutex));
        zfree(l);
    }
}

list_item * list_add_element(list * l, void * ptr) 
{
    list_item      *li;

    pthread_mutex_lock(&(l->mutex));

    li = (list_item *) zmalloc(sizeof(list_item));
    li->value = ptr;
    li->next = NULL;
    li->prev = l->tail;

    if (l->tail == NULL) {
        l->head = l->tail = li;
    } else {
        l->tail = li;
    }
    l->count++;

    pthread_mutex_unlock(&(l->mutex));

    return li;
}

int
list_remove_element(l, ptr)
    list           *l;
    void           *ptr;
{
    int     result = 0;
    list_item      *li = l->head;

    pthread_mutex_lock(&(l->mutex));

    while (li != NULL) {
        if (li->value == ptr) {
            if (li->prev == NULL) {
                l->head = li->next;
            } else {
                li->prev->next = li->next;
            }

            if (li->next == NULL) {
                l->tail = li->prev;
            } else {
                li->next->prev = li->prev;
            }
            l->count--;
            zfree(li);
            result = 1;
            break;
        }
        li = li->next;
    }

    pthread_mutex_unlock(&(l->mutex));

    return result;
}

void
list_each_element(l, func)
    list           *l;
    int             (*func) (list_item *);
{
    list_item      *li;

    pthread_mutex_lock(&(l->mutex));

    li = l->head;
    while (li != NULL) {
        if (func(li) == 1) {
            break;
        }
        li = li->next;
    }

    pthread_mutex_unlock(&(l->mutex));
}
/******* r3/src/node.c *******/
/* #include "config.h" */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

// PCRE
#include <pcre.h>

/* #include "r3.h" */
/* #include "r3_str.h" */
/* #include "slug.h" */
/* #include "zmalloc.h" */


#define CHECK_PTR(ptr) if (ptr == NULL) return NULL;

// String value as the index http://judy.sourceforge.net/doc/JudySL_3x.htm


static int strndiff(char * d1, char * d2, unsigned int n) {
    char * o = d1;
    while ( *d1 == *d2 && n-- > 0 ) {
        d1++;
        d2++;
    }
    return d1 - o;
}

static int strdiff(char * d1, char * d2) {
    char * o = d1;
    while( *d1 == *d2 ) {
        d1++;
        d2++;
    }
    return d1 - o;
}


/**
 * Create a node object
 */
node * r3_tree_create(int cap) {
    node * n = (node*) zmalloc( sizeof(node) );
    CHECK_PTR(n);

    n->edges = (edge**) zmalloc( sizeof(edge*) * cap );
    n->edge_len = 0;
    n->edge_cap = cap;

    n->routes = NULL;
    n->route_len = 0;
    n->route_cap = 0;

    n->endpoint = 0;
    n->combined_pattern = NULL;
    n->pcre_pattern = NULL;
    n->pcre_extra = NULL;
    return n;
}

void r3_tree_free(node * tree) {
    for (int i = 0 ; i < tree->edge_len ; i++ ) {
        if (tree->edges[i]) {
            r3_edge_free(tree->edges[ i ]);
        }
    }
    zfree(tree->edges);
    zfree(tree->routes);

    if (tree->pcre_pattern) {
        pcre_free(tree->pcre_pattern);
    }
#ifdef PCRE_STUDY_JIT_COMPILE
    if (tree->pcre_extra) {
        pcre_free_study(tree->pcre_extra);
    }
#endif
    zfree(tree->combined_pattern);
    zfree(tree);
    tree = NULL;
}



/**
 * Connect two node objects, and create an edge object between them.
 */
edge * r3_node_connectl(node * n, const char * pat, int len, int dupl, node *child) {
    // find the same sub-pattern, if it does not exist, create one
    edge * e;

    e = r3_node_find_edge(n, pat, len);
    if (e) {
        return e;
    }

    if (dupl) {
        pat = zstrndup(pat, len);
    }
    e = r3_edge_createl(pat, len, child);
    CHECK_PTR(e);
    r3_node_append_edge(n, e);
    return e;
}

void r3_node_append_edge(node *n, edge *e) {
    if (n->edges == NULL) {
        n->edge_cap = 3;
        n->edges = zmalloc(sizeof(edge) * n->edge_cap);
    }
    if (n->edge_len >= n->edge_cap) {
        n->edge_cap *= 2;
        edge ** p = zrealloc(n->edges, sizeof(edge) * n->edge_cap);
        if(p) {
            n->edges = p;
        }
    }
    n->edges[ n->edge_len++ ] = e;
}


/**
 * Find the existing edge with specified pattern (include slug)
 *
 * if "pat" is a slug, we should compare with the specified pattern.
 */
edge * r3_node_find_edge(const node * n, const char * pat, int pat_len) {
    edge * e;
    int i;
    for (i = 0 ; i < n->edge_len ; i++ ) {
        e = n->edges[i];

        // there is a case: "{foo}" vs "{foo:xxx}",
        // we should return the match result: full-match or partial-match 
        if ( strcmp(e->pattern, pat) == 0 ) {
            return e;
        }
    }
    return NULL;
}

int r3_tree_compile(node *n, char **errstr)
{
    int ret = 0;
    bool use_slug = r3_node_has_slug_edges(n);
    if ( use_slug ) {
        if ( (ret = r3_tree_compile_patterns(n, errstr)) ) {
            return ret;
        }
    } else {
        // use normal text matching...
        n->combined_pattern = NULL;
    }

    for (int i = 0 ; i < n->edge_len ; i++ ) {
        if ( (ret = r3_tree_compile(n->edges[i]->child, errstr)) ) {
            return ret; // stop here if error occurs
        }
    }
    return 0;
}


/**
 * This function combines ['/foo', '/bar', '/{slug}'] into (/foo)|(/bar)|/([^/]+)}
 *
 * Return -1 if error occurs
 * Return 0 if success
 */
int r3_tree_compile_patterns(node * n, char **errstr) {
    char * cpat;
    char * p;

    cpat = zcalloc(sizeof(char) * 220); // XXX
    if (!cpat) {
        asprintf(errstr, "Can not allocate memory");
        return -1;
    }

    p = cpat;

    edge *e = NULL;
    int opcode_cnt =  0;
    for ( int i = 0 ; i < n->edge_len ; i++ ) {
        e = n->edges[i];

        if ( e->opcode )
            opcode_cnt++;

        if ( e->has_slug ) {
            // compile "foo/{slug}" to "foo/[^/]+"
            char * slug_pat = slug_compile(e->pattern, e->pattern_len);
            strcat(p, slug_pat);
        } else {
            strncat(p,"^(", 2);
            p += 2;

            strncat(p, e->pattern, e->pattern_len);
            p += e->pattern_len;

            strncat(p++,")", 1);
        }

        if ( i + 1 < n->edge_len && n->edge_len > 1 ) {
            strncat(p++,"|",1);
        }
    }

    info("pattern: %s\n",cpat);

    // if all edges use opcode, we should skip the combined_pattern.
    if ( opcode_cnt == n->edge_len ) {
        // zfree(cpat);
        n->compare_type = NODE_COMPARE_OPCODE;
    } else {
        n->compare_type = NODE_COMPARE_PCRE;
    }

    n->combined_pattern = cpat;

    const char *pcre_error;
    int pcre_erroffset;
    unsigned int option_bits = 0;

    n->ov_cnt = (1 + n->edge_len) * 3;

    if (n->pcre_pattern) {
        pcre_free(n->pcre_pattern);
    }
    n->pcre_pattern = pcre_compile(
            n->combined_pattern,              /* the pattern */
            option_bits,                                /* default options */
            &pcre_error,               /* for error message */
            &pcre_erroffset,           /* for error offset */
            NULL);                /* use default character tables */
    if (n->pcre_pattern == NULL && pcre_error != NULL) {
        if (errstr) {
            asprintf(errstr, "PCRE compilation failed at offset %d: %s, pattern: %s", pcre_erroffset, pcre_error, n->combined_pattern);
        }
        return -1;
    }
#ifdef PCRE_STUDY_JIT_COMPILE
    if (n->pcre_extra) {
 