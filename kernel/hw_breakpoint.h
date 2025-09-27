#ifndef HW_BREAKPOINT_H
#define HW_BREAKPOINT_H

#include "comm.h"
#include <linux/stdbool.h>

int handle_set_hw_breakpoint(PHW_BREAKPOINT_CTL ctl, bool enable);

#endif // HW_BREAKPOINT_H
