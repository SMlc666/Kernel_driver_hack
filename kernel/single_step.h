#ifndef SINGLE_STEP_H
#define SINGLE_STEP_H

#include "comm.h"

int handle_single_step_control(PSINGLE_STEP_CTL ctl);
int single_step_init(void);
void single_step_exit(void);

#endif // SINGLE_STEP_H
