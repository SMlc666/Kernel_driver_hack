#ifndef TOUCH_SHARED_H
#define TOUCH_SHARED_H

// 为了在内核和用户空间都能使用，只包含双方共有的头文件
#include <stdint.h>

#define MAX_TOUCH_POINTS 10
#define MAX_USER_COMMANDS (MAX_TOUCH_POINTS * 2)
#define KERNEL_BUFFER_FRAMES 32 // 环形缓冲区的大小

// 触摸点状态，由内核写入
// 使用固定的int类型以保证跨架构的兼容性
struct KernelTouchPoint {
    int32_t tracking_id;    // 触摸点的唯一跟踪ID
    int32_t slot;           // 该触摸点所在的硬件槽位
    uint32_t is_active;     // 此槽位当前是否活跃 (用uint32代替bool)
    int32_t x, y;           // 坐标
    int32_t pressure;       // 压力值
};

// 代表一个完整的触摸状态帧
struct TouchFrame {
    int32_t touch_count;
    struct KernelTouchPoint touches[MAX_TOUCH_POINTS];
};

// 用户指令动作
enum UserAction {
    ACTION_IGNORE = 0,      // 忽略此点（拦截）
    ACTION_PASS_THROUGH = 1,// 原样放行此原始触摸点
    ACTION_MODIFY = 2,      // 修改此触摸点
    ACTION_INJECT = 3,      // 注入一个全新的触摸点
    ACTION_UP = 4,          // 显式声明一个触摸点抬起
};

// 用户指令，由用户层写入
struct UserCommand {
    enum UserAction action;
    int32_t slot;

    struct {
        int32_t x, y;
        int32_t pressure;
        int32_t tracking_id;
    } new_data;
};

// 共享内存的完整布局
struct SharedTouchMemory {
    // --- 同步与控制区 ---
    volatile uint64_t user_sequence;        // 用于 User -> Kernel 的指令同步
    volatile int32_t user_pid;
    volatile uint64_t last_user_heartbeat;
    volatile uint32_t polling_interval_ms;

    // --- Kernel -> User 环形缓冲区 ---
    volatile uint64_t kernel_write_idx;     // 内核写入位置
    volatile uint64_t user_read_idx;        // 用户读取位置
    struct TouchFrame kernel_frames[KERNEL_BUFFER_FRAMES];

    // --- User -> Kernel 指令缓冲区 ---
    volatile int32_t user_command_count;
    struct UserCommand user_commands[MAX_USER_COMMANDS];
};

#endif // TOUCH_SHARED_H