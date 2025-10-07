#ifndef TOUCH_INPUT_H
#define TOUCH_INPUT_H

#include <linux/fs.h>
#include "comm.h"

// Main initialization and exit points for the touch module
int touch_input_init(void);
void touch_input_exit(void);

// Main dispatcher for touch-related ioctl commands
long handle_touch_ioctl(unsigned int cmd, unsigned long arg);

// mmap handler for the shared buffer
int touch_input_mmap(struct file *filp, struct vm_area_struct *vma);

#endif // TOUCH_INPUT_H
