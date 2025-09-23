#ifndef TOUCH_SHARED_H
#define TOUCH_SHARED_H

// 内核空间应使用 <linux/types.h>
#include <linux/types.h>

#define MAX_TOUCH_POINTS 10
#define MAX_USER_COMMANDS (MAX_TOUCH_POINTS * 2)
#define KERNEL_BUFFER_FRAMES 32 // 环形缓冲区的大小

// 触摸点状态，由内核写入
struct KernelTouchPoint {
    s32 tracking_id;    // 触摸点的唯一跟踪ID
    s32 slot;           // 该触摸点所在的硬件槽位
    u32 is_active;      // 此槽位当前是否活跃
    s32 x, y;           // 坐标
    s32 pressure;       // 压力值
};

// 代表一个完整的触摸状态帧
struct TouchFrame {
    s32 touch_count;
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
    s32 slot;

    struct {
        s32 x, y;
        s32 pressure;
        s32 tracking_id;
    } new_data;
};

// 共享内存的完整布局
struct SharedTouchMemory {
    // --- 同步与控制区 ---
    volatile u64 user_sequence;        // 用于 User -> Kernel 的指令同步
    volatile s32 user_pid;
    volatile u64 last_user_heartbeat;
    volatile u32 polling_interval_ms;

    // --- Kernel -> User 环形缓冲区 ---
    volatile u64 kernel_write_idx;     // 内核写入位置
    volatile u64 user_read_idx;        // 用户读取位置
    struct TouchFrame kernel_frames[KERNEL_BUFFER_FRAMES];

    // --- User -> Kernel 指令缓冲区 ---
    volatile s32 user_command_count;
    struct UserCommand user_commands[MAX_USER_COMMANDS];
};

#endif // TOUCH_SHARED_H
