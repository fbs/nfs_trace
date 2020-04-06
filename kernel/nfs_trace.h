// Copyright (C) 2020 bas smit
// SPDX-License-Identifier:  GPL-2.0-or-later

#include <linux/types.h>
#include <linux/ioctl.h>

#define IOC_MAGIC 'x'
#define NT_IOC_DROPPED _IOR(IOC_MAGIC, 1, __u64)
#define NT_IOC_EVENTS  _IOR(IOC_MAGIC, 2, __u64)

typedef struct {
  char type;
  char path[255];
} nt_event_t;
