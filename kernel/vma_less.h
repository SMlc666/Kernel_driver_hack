#ifndef VMA_LESS_H
#define VMA_LESS_H

#include "comm.h"
#include "version_control.h"

#ifdef CONFIG_MEMORY_ACCESS_MODE

int vma_less_init(void);
void vma_less_exit(void);

int handle_vma_less_alloc(PVMA_LESS_ALLOC_CTL ctl);
int handle_vma_less_free(PVMA_LESS_FREE_CTL ctl);
int handle_vma_less_protect(PVMA_LESS_PROTECT_CTL ctl);
int handle_vma_less_query(PVMA_LESS_QUERY_CTL ctl);

#else

static inline int vma_less_init(void) { return 0; }
static inline void vma_less_exit(void) { }

static inline int handle_vma_less_alloc(PVMA_LESS_ALLOC_CTL ctl) { return -ENODEV; }
static inline int handle_vma_less_free(PVMA_LESS_FREE_CTL ctl) { return -ENODEV; }
static inline int handle_vma_less_protect(PVMA_LESS_PROTECT_CTL ctl) { return -ENODEV; }
static inline int handle_vma_less_query(PVMA_LESS_QUERY_CTL ctl) { return -ENODEV; }

#endif // CONFIG_MEMORY_ACCESS_MODE

#endif // VMA_LESS_H
