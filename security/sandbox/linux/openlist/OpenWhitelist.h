/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_OpenWhitelist_h
#define mozilla_OpenWhitelist_h


static const char *openWhitelist[]= {
  "dev/genlock",
  "/dev/ashmem",
  "/dev/ksgl-2d1",
  "/dev/ksgl-2d0",
  "/dev/ksgl-3d0",
  "/dev/urandom",
  "/dev/ion",
  "/proc/cpuinfo",
  "/proc/meminfo",
  "/sys/devices/system/cpu/present",
  "/sys/devices/system/soc/soc0/id",
  "/system/fonts",
  "/system/lib/hw",
  "/system/lib/egl",
  //"/system/lib libGLS"
  "/system/lib/libgenlock.so",
  "/system/lib/libETC1.so",
  "/system/lib/libgsl.so",
  "/system/lib/libsc-a2xx.so",
  "/system/b2g/dictionnaries",
  "/etc/media_profiles.xml",
  "/system/lib/libOpenSLES.so",
  "/system/lib/libwilhelm.so",
  //video hacks
  // /system/lib libstagefright
  // /system/lib libmm
  // /system/lib libOmx
  "/system/lib/libDivxDrm.so",
  "/system/b2g/libsoftokn3.so",
  "/system/b2g/libfreebl3.so",
  "/sys/kernel/debug/tracing/trace_marker"
};

//XXX: create two arrays for read and write

//Pathnames from openWhitelist put in one big array
extern __attribute__ ((visibility("default"))) char *AlignedOpenWhitelist;

//Stores addresses of the beginning of strings in AlignedOpenWhitelist
extern __attribute__ ((visibility("default"))) char **AlignedOpenWhitelistAddresses; 

//Number of pathnames in AlignedOpenWhitelist
extern __attribute__ ((visibility("default"))) size_t AlignedOpenWhitelistSize;


namespace mozilla {

extern __attribute__ ((visibility("default"))) int InitWhitelistAddresses();

} // namespace mozilla

#endif // mozilla_OpenWhitelist_h


