/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
//#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/stat.h>
#include <sys/stat.h>
#include "prenv.h"
#include "OpenWhitelist.h" 
#include <stdarg.h>

#define NS_EXPORT __attribute__ ((visibility("default")))

#ifdef MOZ_WIDGET_GONK
#define WRAP(x) x
#else
#define WRAP(x) __wrap_##x
#endif


typedef int (*orig_open_func_type)(const char *pathname, int flags, ...);
typedef off_t fpos_t;

#define O_APPEND 00002000
#define O_CREAT 00000100
//XXX: ARM specific
#define O_LARGEFILE 0400000
#define DEFFILEMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) /* 0666 */


int
filteredOpen(const char *pathname, int flags, int mode)
{
  orig_open_func_type orig_func;
  char *e = getenv("CONTENT_IS_SANDBOXED");  
  int i = 0;
  int r = -1;
  char *addr = NULL;
  if (e != NULL) {
    if (strncmp(e, "1", 1) == 0){
      __android_log_print(ANDROID_LOG_WARN, "Sandbox", "SANDBOXED OPEN: %s %08X %d", pathname, pathname, flags);
    
      for(i=0; i < AlignedOpenWhitelistSize; i++) {
        addr = AlignedOpenWhitelistAddresses[i];
        //__android_log_print(ANDROID_LOG_WARN, "Sandbox", "AlignedOpenWhitelistAddresses[%d]: %s %08X", i, addr, addr);
        if (strlen(pathname) == strlen(addr)) {
          r = strcmp(pathname, addr);
          if (r == 0){
            __android_log_print(ANDROID_LOG_WARN, "Sandbox","AlignedOpenWhitelistAddresses[%d]: %s %08X", i, addr, addr); 
            __android_log_print(ANDROID_LOG_WARN, "Sandbox", "FOUND");
            orig_func = (orig_open_func_type)dlsym(RTLD_NEXT, "open");
            __android_log_print(ANDROID_LOG_WARN, "Sandbox", "orig_func: %08X %s %d", orig_func, addr, flags);
            return orig_func(addr, flags, mode);
          }
        }
      }
      __android_log_print(ANDROID_LOG_WARN, "Sandbox", "Forbidden call");
      return -1;
    }
  }
     
  //If content not sandboxed: 
  orig_func = (orig_open_func_type)dlsym(RTLD_NEXT, "open");
  r = orig_func(pathname, flags, mode);
  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "open result: %s %d result: %d", pathname, flags, r);
  return r;
}

extern "C" NS_EXPORT int 
WRAP(open)(const char *pathname, int flags, ...)
{
  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "OPEN %s", pathname);
  mode_t mode = 0;

  flags |= O_LARGEFILE;
  if (flags & O_CREAT)
  {
    va_list args;
    va_start(args, flags);
    mode = (mode_t) va_arg(args, int);
    va_end(args);
  }

  return filteredOpen(pathname, flags, mode);
  
}

extern "C" NS_EXPORT FILE* 
WRAP(fopen)(const char *file, const char* mode)
{

  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "FOPEN %s", file);
	
  FILE *fp;
	int f;
	int flags, oflags;

  void *handle;
  int (*__sflags)(const char *, int *);
  FILE *(*__sfp)(void);
  fpos_t (*__sseek)(void *, fpos_t, int);
  int (*__sclose)(void *);
  int (*__sread)(void *, char *, int);
  int (*__swrite)(void *, const char *, int);

  *(void **) (&__sflags)  = dlsym(RTLD_DEFAULT, "__sflags");
  //if (__sflags == NULL)
  //  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "__sflags NULL");
  
  *(void **) (&__sfp) = dlsym(RTLD_DEFAULT, "__sfp");
  //if (__sfp == NULL)
  //  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "__sfp NULL");
  
  *(void **) &(__sseek) = dlsym(RTLD_DEFAULT, "__sseek");
  //if (__sseek == NULL)
  //  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "__sseek NULL");
  
  *(void **) (&__sclose)  = dlsym(RTLD_DEFAULT, "__sclose");
  //if (__sclose == NULL)
  //  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "__sclose NULL");
  
  *(void **) (&__sread)  = dlsym(RTLD_DEFAULT, "__sread");
  //if (__sread == NULL)
  //  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "__sread NULL");
  
  *(void **) (&__swrite)  = dlsym(RTLD_DEFAULT, "__swrite");
  //if (__swrite == NULL)
  //  __android_log_print(ANDROID_LOG_WARN, "Sandbox", "__swrite NULL");

	if ((flags = __sflags(mode, &oflags)) == 0){
    //__android_log_print(ANDROID_LOG_WARN, "Sandbox", "fail flags");
    return (NULL);
  }
	if ((fp = __sfp()) == NULL){
    //__android_log_print(ANDROID_LOG_WARN, "Sandbox", "fail sfp");
		return (NULL);
  }

  f = filteredOpen(file, oflags, DEFFILEMODE);
	if (f < 0) {
		fp->_flags = 0;			// release 
    __android_log_print(ANDROID_LOG_WARN, "Sandbox", "c'est NULL");
		return (NULL);
	}
 
	fp->_file = f;
	fp->_flags = flags;
	fp->_cookie = fp;
	fp->_read = __sread;
	fp->_write = __swrite;
	fp->_seek = __sseek;
	fp->_close = __sclose;

  if (oflags & O_APPEND){
		(void) __sseek((void *)fp, (fpos_t)0, SEEK_END);
  }
  return (fp);
}
