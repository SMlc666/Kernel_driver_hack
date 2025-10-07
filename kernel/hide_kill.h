#ifndef _HIDE_KILL_H
#define _HIDE_KILL_H

#include "version_control.h"

#ifdef CONFIG_HIDE_PROC_MODE

int hide_kill_init(void);
void hide_kill_exit(void);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int hide_kill_init(void) { return 0; }
static inline void hide_kill_exit(void) { }

#endif

#endif // _HIDE_KILL_H
