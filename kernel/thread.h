#ifndef THREAD_H
#define THREAD_H

#include "comm.h"

int handle_thread_control(PTHREAD_CTL ctl);
int handle_enum_threads(PENUM_THREADS et);

#endif // THREAD_H
