#ifndef SPAWN_SUSPEND_H
#define SPAWN_SUSPEND_H

#include <linux/types.h>
#include "version_control.h"

#ifdef CONFIG_SPAWN_SUSPEND_MODE

int spawn_suspend_init(void);
void spawn_suspend_exit(void);
void set_spawn_suspend_target(const char *name, int enable);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int spawn_suspend_init(void) { return 0; }
static inline void spawn_suspend_exit(void) { }
static inline void set_spawn_suspend_target(const char *name, int enable) { }

#endif

#endif // SPAWN_SUSPEND_H
