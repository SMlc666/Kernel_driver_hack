#ifndef SPAWN_SUSPEND_H
#define SPAWN_SUSPEND_H

#include <linux/types.h>

int spawn_suspend_init(void);
void spawn_suspend_exit(void);
void set_spawn_suspend_target(const char *name, int enable);

#endif // SPAWN_SUSPEND_H
