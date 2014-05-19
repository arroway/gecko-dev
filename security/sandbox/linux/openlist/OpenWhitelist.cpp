/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <unistd.h>
#include <stdlib.h>
#include "nsString.h"
#include <sys/mman.h>
#include "OpenWhitelist.h"
#if defined(ANDROID)
#include "../android_ucontext.h"
#include <android/log.h>
#endif

#ifdef MOZ_LOGGING
#define FORCE_PR_LOG 1
#endif
#include "prlog.h"
#include "prenv.h"

char *AlignedOpenWhitelist;
char **AlignedOpenWhitelistAddresses;
size_t AlignedOpenWhitelistSize;

namespace mozilla {

#if defined(ANDROID)
#define LOG_ERROR(args...) __android_log_print(ANDROID_LOG_ERROR, "Sandbox", ## args)
#elif defined(PR_LOGGING)
static PRLogModuleInfo* gSeccompSandboxLog;
#define LOG_ERROR(args...) PR_LOG(gSeccompSandboxLog, PR_LOG_ERROR, (args))
#else
#define LOG_ERROR(args...)
#endif

int
InitWhitelistAddresses() {
  int pagesize;
  struct sigaction sa;
  int r = -1;
  int i = 0;
  int j = 0;
  size_t size = 0;

  /*sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1) {
    LOG_ERROR("sigaction");
    return 1;
  }*/
  
  pagesize = sysconf(_SC_PAGE_SIZE);
  if (pagesize == -1) {
    LOG_ERROR("sysconf");
    return 1;
  }

  void *tmp_ptr;
  //XXX calculate size given openWhitelist size
  r = posix_memalign(&tmp_ptr, 4096, 4096);
  if (tmp_ptr == NULL) {
    LOG_ERROR("memalign");
    return 1;
  }

  //posix_memaligned doesn't zero out memory
  memset(tmp_ptr, 0, pagesize);

  AlignedOpenWhitelistAddresses = (char **)tmp_ptr;
 
  r = posix_memalign((void **) &AlignedOpenWhitelist, 4096, 8192);
  if (AlignedOpenWhitelist == NULL) {
    LOG_ERROR("memalign");
    return 1;
  }

  memset(AlignedOpenWhitelist, 0, pagesize);

  size = sizeof(openWhitelist)/sizeof(openWhitelist[0]);
  for (i = 0; i < size; i++) {
    //LOG_ERROR("openWhitelist[%d]: %s %08X", i, openWhitelist[i], openWhitelist[i]);
    //LOG_ERROR("AlignedOpenWhitelist[%d]: %08X", j, AlignedOpenWhitelist[j]);
    strcpy(&AlignedOpenWhitelist[j], openWhitelist[i]);
    //LOG_ERROR("After assignment: AlignedOpenWhitelist[%d]: %c %08X", j, AlignedOpenWhitelist[j], AlignedOpenWhitelist[j]);
    AlignedOpenWhitelistAddresses[i] = &AlignedOpenWhitelist[j];
    //LOG_ERROR("After assignment: AlignedOpenWhitelistAddresses[%d]: %s %08X", i, AlignedOpenWhitelistAddresses[i], AlignedOpenWhitelistAddresses[i]);
    j += strlen(openWhitelist[i]) + 1;
  }

  AlignedOpenWhitelistSize = i;
  return 0;
}

} //namespace mozilla
