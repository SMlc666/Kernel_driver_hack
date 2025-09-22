#ifndef TOUCH_CONTROL_H
#define TOUCH_CONTROL_H

#include <linux/types.h>

// Initializes the touch control subsystem
int touch_control_init(void *shared_mem_ptr);

// Exits the touch control subsystem
void touch_control_exit(void);

// Starts the hijack and the kernel thread
int touch_control_start_hijack(const char *device_name);

// Stops the hijack and the kernel thread
void touch_control_stop_hijack(void);

#endif // TOUCH_CONTROL_H
