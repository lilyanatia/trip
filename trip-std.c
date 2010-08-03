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

/* This tripcode searcher uses only features specified by ISO C89 and POSIX:
 *  # POSIX regular expressions instead of PCRE
 *  # no compiler-specific code
 *  # system crypt() instead of OpenSSL's des_fcrypt()
 */

#include <pthread.h>
#include <regex.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint32_t global_z[4];

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

void *trip_search(void *);

int main(int argc, char *argv[])
{ int threads = 1, c, i, errcode, regopt = REG_NOSUB | REG_ICASE;
  char *searchstring;
  regex_t regex;
  srand48(time(0));
  unsigned short seed16v[3];
  seed16v[0] = lrand48();
  seed16v[1] = lrand48();
  seed16v[2] = lrand48();
  init_lfsr113(seed16v, global_z);
  while((c = getopt(argc, argv, "cEt:")) != -1)
    switch(c)
    { case 'c':
        regopt &= !REG_NOSUB;
        break;
      case 'E':
        regopt |= REG_EXTENDED;
        break;
      case 't':
        if(atoi(optarg)) threads = atoi(optarg);
        break;
      case '?':
        printf("Usage: %s [-c] [-E] [-t threads] [regex]\n", argv[0]);
        return 1;
      default:
        abort();
    }
  if(optind < argc)
    searchstring = argv[optind];
  else
  { searchstring = "";
    regopt = REG_NOSUB; }
  errcode = regcomp(&regex, searchstring, regopt);
  if(errcode)
  { int errsize = regerror(errcode, &regex, NULL, 0);
    char *errptr = NULL;
    regerror(errcode, &regex, errptr, errsize);
    fputs(errptr, stderr);
    abort(); }
  for(i = 0; i < threads - 1; ++i)
  { pthread_t thread;
    if(pthread_create(&thread, NULL, &trip_search, &regex))
      fputs("failed to start a thread.", stderr); }
 trip_search((void*)&regex);
 return(0); }

void *trip_search(void *p)
{ const char tripc[] = " !#$%()*+-./0123456789:;=?ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\"
   "]^_`abcdefghijklmnopqrstuvwxyz{|}~";
  const char saltc[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
   "rstuvwxyz";
  char salt[2] = {0}, cap[24] = "xxxxxxxx  =  xxxxxxxxxx\n";
  char *trip = cap + 13;
  regex_t *regex = p;
  int i;
  uint32_t z[4];
  unsigned short seed16v[3];
  seed16v[0] = lfsr113(global_z);
  seed16v[1] = lfsr113(global_z);
  seed16v[2] = lfsr113(global_z);
  init_lfsr113(seed16v, z);
  for(;;)
  { cap[0] = tripc[lfsr113(z) % (sizeof(tripc) - 1)];
    salt[0] = saltc[lfsr113(z) % (sizeof(saltc) - 1)];
    salt[1] = saltc[lfsr113(z) % (sizeof(saltc) - 1)];
    memcpy(cap + 1, salt, 2);
    for(i = 3; i < 7; ++i)
      cap[i] = tripc[lfsr113(z) % (sizeof(tripc) - 1)];
    cap[7] = tripc[lfsr113(z) % (sizeof(tripc) - 1)];
    memcpy(trip, crypt(cap, salt) + 3, 10);
    if(!regexec(regex, trip, 0, NULL, 0))
      fwrite(cap, 24, 1, stdout); }
  return NULL; }
