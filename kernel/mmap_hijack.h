#ifndef MMAP_HIJACK_H
#define MMAP_HIJACK_H

#include "comm.h"
#include "version_control.h"

#ifdef CONFIG_MEMORY_ACCESS_MODE

int handle_map_memory(PMAP_MEMORY_CTL ctl);

#else

static inline int handle_map_memory(PMAP_MEMORY_CTL ctl) { return -ENODEV; }

#endif // CONFIG_MEMORY_ACCESS_MODE

#endif // MMAP_HIJACK_H
