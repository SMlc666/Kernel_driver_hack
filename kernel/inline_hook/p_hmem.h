/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_HMEM_H_
#define _KP_HMEM_H_

#include "p_hook.h"

int hook_mem_add(u64 start, s32 size);
void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type);
void hook_mem_free(void *hook_mem);
void *hook_get_mem_from_origin(u64 origin_addr);

#endif