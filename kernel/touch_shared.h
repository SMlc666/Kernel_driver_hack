#ifndef TOUCH_SHARED_H
#define TOUCH_SHARED_H

// 内核空间使用的版本
#include <linux/types.h>

#define MAX_TOUCH_POINTS 10
#define MAX_USER_COMMANDS (MAX_TOUCH_POINTS * 2)

struct KernelTouchPoint {
    int32_t tracking_id;
    int32_t slot;
    uint32_t is_active;
    int32_t x, y;
    int32_t pressure;
};

enum UserAction {
    ACTION_IGNORE = 0,
    ACTION_PASS_THROUGH = 1,
    ACTION_MODIFY = 2,
    ACTION_INJECT = 3,
};

struct UserCommand {
    enum UserAction action;
    int32_t original_tracking_id; 
    
    struct {
        int32_t x, y;
        int32_t pressure;
    } new_data;
};

struct SharedTouchMemory {
    volatile uint64_t kernel_sequence;
    volatile uint64_t user_sequence;
    volatile uint32_t polling_interval_ms;
    volatile int32_t user_pid;
    volatile uint64_t last_user_heartbeat;

    volatile int32_t kernel_touch_count;
    struct KernelTouchPoint kernel_touches[MAX_TOUCH_POINTS];

    volatile int32_t user_command_count;
    struct UserCommand user_commands[MAX_USER_COMMANDS];
};

#endif // TOUCH_SHARED_H
