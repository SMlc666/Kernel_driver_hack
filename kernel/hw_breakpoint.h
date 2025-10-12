#ifndef HW_BREAKPOINT_H
#define HW_BREAKPOINT_H

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include "comm.h"
#include "version_control.h"

#ifdef CONFIG_HW_BREAKPOINT_MODE

int hw_breakpoint_init(void);
void hw_breakpoint_exit(void);
int handle_hw_breakpoint_control(PHW_BREAKPOINT_CTL ctl);
int handle_hw_breakpoint_get_hits(PHW_BREAKPOINT_GET_HITS_CTL ctl, unsigned long arg);

#else

static inline int hw_breakpoint_init(void) { return 0; }
static inline void hw_breakpoint_exit(void) { }
static inline int handle_hw_breakpoint_control(PHW_BREAKPOINT_CTL ctl) { return -ENODEV; }
static inline int handle_hw_breakpoint_get_hits(PHW_BREAKPOINT_GET_HITS_CTL ctl, unsigned long arg) { return -ENODEV; }

#endif // CONFIG_HW_BREAKPOINT_MODE

#endif // HW_BREAKPOINT_H
