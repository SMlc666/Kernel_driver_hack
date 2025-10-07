#ifndef SINGLE_STEP_H
#define SINGLE_STEP_H

#include "comm.h"
#include "version_control.h"

#ifdef CONFIG_SINGLE_STEP_MODE

extern pid_t g_target_tid; // Make accessible to other files
extern struct user_pt_regs g_last_regs; // Make accessible to other files
extern bool g_regs_valid; // Make accessible to other files
extern bool g_is_general_suspend; // Make accessible to other files - indicates general suspend mode

int handle_single_step_control(PSINGLE_STEP_CTL ctl);
int single_step_init(void);
void single_step_exit(void);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int handle_single_step_control(PSINGLE_STEP_CTL ctl) { return 0; }
static inline int single_step_init(void) { return 0; }
static inline void single_step_exit(void) { }

// Define dummy variables
static inline pid_t get_g_target_tid(void) { return 0; }
static inline struct user_pt_regs get_g_last_regs(void) { struct user_pt_regs r = {0}; return r; }
static inline bool get_g_regs_valid(void) { return false; }

#endif

#endif // SINGLE_STEP_H
