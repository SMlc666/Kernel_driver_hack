#ifndef _HIDE_PROC_H
#define _HIDE_PROC_H

#include <linux/types.h>

int hide_proc_init(void);
void hide_proc_exit(void);
void add_hidden_pid(pid_t pid);
void remove_hidden_pid(pid_t pid);
bool is_pid_hidden(pid_t pid);
void clear_hidden_pids(void);

#endif