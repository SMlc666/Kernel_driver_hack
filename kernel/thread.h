#ifndef THREAD_H
#define THREAD_H

#include "comm.h"
#include "version_control.h"

#ifdef CONFIG_THREAD_CONTROL_MODE

int handle_thread_control(PTHREAD_CTL ctl);
int handle_enum_threads(PENUM_THREADS et);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int handle_thread_control(PTHREAD_CTL ctl) { return -ENODEV; }
static inline int handle_enum_threads(PENUM_THREADS et) { return -ENODEV; }

#endif // CONFIG_THREAD_CONTROL_MODE

#endif // THREAD_H
