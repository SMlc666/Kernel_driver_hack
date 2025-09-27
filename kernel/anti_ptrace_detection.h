#ifndef ANTI_PTRACE_DETECTION_H
#define ANTI_PTRACE_DETECTION_H

#include "version_control.h"

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE

int start_anti_ptrace_detection(void);
void stop_anti_ptrace_detection(void);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int start_anti_ptrace_detection(void) { return 0; }
static inline void stop_anti_ptrace_detection(void) { }

#endif

#endif // ANTI_PTRACE_DETECTION_H
