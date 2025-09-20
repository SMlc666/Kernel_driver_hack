#ifndef EVENT_HIJACK_H
#define EVENT_HIJACK_H

#include <linux/input.h>
#include "comm.h"

// Initialize the hijacking subsystem
void event_hijack_init(void);

// Clean up the hijacking subsystem
void event_hijack_exit(void);

// Functions to be called by ioctl
int do_hook_input_device(const char *name);
int do_read_input_events(PEVENT_PACKAGE user_pkg);
int do_inject_input_event(struct input_event *event);
int do_inject_input_package(PEVENT_PACKAGE user_pkg);
void do_cleanup_hook(void);

// Check if the hook is currently active
bool is_hook_active(void);

#endif // EVENT_HIJACK_H
