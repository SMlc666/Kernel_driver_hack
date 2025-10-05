#ifndef SINGLE_STEP_H
#define SINGLE_STEP_H

#include "comm.h"

extern pid_t g_target_tid; // Make accessible to other files
extern struct user_pt_regs g_last_regs; // Make accessible to other files
extern bool g_regs_valid; // Make accessible to other files

int handle_single_step_control(PSINGLE_STEP_CTL ctl);
int single_step_init(void);
void single_step_exit(void);

#endif // SINGLE_STEP_H
