/*
 * Copyright (c) 2005-2010 robert wilson
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/des.h>
#include <pcre.h>
#include <pthread.h>

#ifndef HEADER_NEW_DES_H
#define DES_fcrypt des_fcrypt
#endif

#ifdef __predict_false
#define probably_false(x) __predict_false(x)
#else
#define probably_false(x) (x)
#endif

static inline uint32_t lfsr113(uint32_t z[4])
{ z[0] = ((z[0] & 4294967294) << 18) ^ ((((z[0] << 6) ^ z[0]) & UINT32_MAX) >>
   13);
  z[1] = ((z[1] & 4294967288) << 2) ^ ((((z[1] << 2) ^ z[1]) & UINT32_MAX) >>
   27);
  z[2] = ((z[2] & 4294967280) << 7) ^ ((((z[2] << 13) ^ z[2]) & UINT32_MAX) >>
   21);
  z[3] = ((z[3] & 4294967168) << 13) ^ ((((z[3] << 3) ^ z[3]) & UINT32_MAX) >>
   12);
  return z[0] ^ z[1] ^ z[2] ^ z[3]; }

static inline void init_lfsr113(unsigned short seed16v[3], uint32_t z[4])
{ unsigned short *xsubi = seed48(seed16v);
  z[0] = nrand48(xsubi);
  z[1] = nrand48(xsubi);
  z[2] = nrand48(xsubi);
  z[3] = nrand48(xsubi);
  for(int i = 0; i < 256; ++i) lfsr113(z); }

static inline uint32_t my_rand(uint32_t z[4], uint32_t n)
{ if(!n) return 0;
  uint32_t ret, max_value = UINT32_MAX / n * n;
  while((ret = lfsr113(z)) > max_value);
  ret /= UINT32_MAX / n;
  return ret; }

typedef struct
{ int regopt;
  char *searchstring;
  uint32_t z[4]; } search_params;

void *trip_search(void *);

int main(int argc, char *argv[])
{ int threads = 1, processes = 1, c;
  search_params sp;
  unsigned short seed16v[3];
  sp.regopt = PCRE_CASELESS | PCRE_NO_AUTO_CAPTURE;
  while((c = getopt(argc, argv, "cp:t:")) != -1)
    switch(c)
    { case 'c':
        sp.regopt = PCRE_NO_AUTO_CAPTURE;
        break;
      case 't':
        if(atoi(optarg)) threads = atoi(optarg);
        break;
      case 'p':
        if(atoi(optarg)) processes = atoi(optarg);
        break;
      case '?':
        printf("Usage: %s [-c] [-p processes] [-t threads] [regex]\n", argv[0]);
        return 1;
      default:
        abort(); }
  if(optind < argc)
    sp.searchstring = argv[optind];
  else
  { sp.searchstring = "";
    sp.regopt = PCRE_NO_AUTO_CAPTURE; }
  srand48(time(0));
  for(int i = 0; i < processes - 1; ++i)
  { if(!fork()) break; 
    srand48(lrand48()); }
  seed16v[0] = lrand48();
  seed16v[1] = lrand48();
  seed16v[2] = lrand48();
  init_lfsr113(seed16v, sp.z);
  for(int i = 0; i < threads - 1; ++i)
  { pthread_t thread;
    if(pthread_create(&thread, NULL, &trip_search, &sp))
      fputs("failed to start a thread.", stderr); }
  trip_search(&sp);
  return(0); }

void *trip_search(void *p)
{ const char tripc[] = " !#$%()*+-./0123456789:;=?ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\"
   "]^_`abcdefghijklmnopqrstuvwxyz{|}~";
  const char saltc[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
   "rstuvwxyz";
  char salt[2] = {0}, cap[24] = {0};
  char *errptr, *temp = cap + 10, *trip = temp + 3;
  int erroffset, oveclen;
  int *ovector;
  pcre *regex;
  pcre_extra *regex_extra;
  search_params *sp = p;
  uint32_t z[4];
  unsigned short seed16v[3];
  seed16v[0] = lfsr113(sp->z);
  seed16v[1] = lfsr113(sp->z);
  seed16v[2] = lfsr113(sp->z);
  init_lfsr113(seed16v, z);
  cap[8] = cap[9] = ' ';
  regex = pcre_compile(sp->searchstring, sp->regopt, (const char **)&errptr,
   &erroffset, 0);
  if(!regex)
  { fputs(errptr, stderr);
    abort(); }
  regex_extra = pcre_study(regex, 0, (const char **)&errptr);
  if(errptr)
  { fputs(errptr, stderr);
    abort(); }
  oveclen = pcre_info(regex, NULL, NULL);
  if(oveclen > 0) oveclen = (oveclen + 1) * 3;
  ovector = calloc(oveclen, sizeof(int));
  for(;;)
  { cap[0] = tripc[my_rand(z, sizeof(tripc) - 1)];
    salt[0] = saltc[my_rand(z, sizeof(saltc) - 1)];
    salt[1] = saltc[my_rand(z, sizeof(saltc) - 1)];
    memcpy(cap + 1, salt, 2);
    for(int i = 3; i < 7; ++i)
      cap[i] = tripc[my_rand(z, sizeof(tripc) - 1)];
    cap[7] = tripc[my_rand(z, sizeof(tripc) - 1)];
    DES_fcrypt(cap, salt, temp);
    if(probably_false(!pcre_exec(regex, regex_extra, trip, 10, 0, 0, ovector,
     oveclen)))
    { cap[10] = '=';
      cap[11] = cap[12] = ' ';
      cap[23] = '\n';
      fwrite(cap, 24, 1, stdout); } } }
