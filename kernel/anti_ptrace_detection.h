#ifndef ANTI_PTRACE_DETECTION_H
#define ANTI_PTRACE_DETECTION_H

#include "cvector.h"
#include <linux/mutex.h>

// Forward declare to avoid circular dependency
struct HWBP_HANDLE_INFO;

int anti_ptrace_init(cvector *p_hwbp_handle_info_arr, struct mutex *p_mutex);
void anti_ptrace_exit(void);

#endif // ANTI_PTRACE_DETECTION_H
