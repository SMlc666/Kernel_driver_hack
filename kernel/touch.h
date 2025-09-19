#ifndef _TOUCH_H
#define _TOUCH_H

#include <linux/input.h>
#include "comm.h"

int touch_init(PTOUCH_INIT_DATA data);
void touch_deinit(void);
void touch_send_event(PTOUCH_DATA data);

#endif