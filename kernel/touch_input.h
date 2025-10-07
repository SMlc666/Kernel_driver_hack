#ifndef TOUCH_INPUT_H
#define TOUCH_INPUT_H

#include <linux/fs.h>
#include "comm.h"
#include "version_control.h"

#ifdef CONFIG_TOUCH_INPUT_MODE

// Main initialization and exit points for the touch module
int touch_input_init(void);
void touch_input_exit(void);

// Main dispatcher for touch-related ioctl commands
long handle_touch_ioctl(unsigned int cmd, unsigned long arg);

// mmap handler for the shared buffer
int touch_input_mmap(struct file *filp, struct vm_area_struct *vma);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int touch_input_init(void) { return 0; }
static inline void touch_input_exit(void) { }
static inline long handle_touch_ioctl(unsigned int cmd, unsigned long arg) { return -ENODEV; }
static inline int touch_input_mmap(struct file *filp, struct vm_area_struct *vma) { return -EIO; }

#endif // CONFIG_TOUCH_INPUT_MODE

#endif // TOUCH_INPUT_H
