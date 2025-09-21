#ifndef _TOUCH_H
#define _TOUCH_H

#include <linux/input.h>
#include "comm.h"

int touch_set_device_by_name(const char *name);
void touch_deinit(void);

#endif