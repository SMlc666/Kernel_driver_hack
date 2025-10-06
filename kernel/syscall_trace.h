#ifndef SYSCALL_TRACE_H
#define SYSCALL_TRACE_H

#include <linux/types.h>
#include <linux/limits.h>
#include "comm.h"

// 系统调用追踪操作
enum SYSCALL_TRACE_ACTION {
    SYSCALL_TRACE_START = 1,
    SYSCALL_TRACE_STOP = 2,
    SYSCALL_TRACE_CLEAR = 3,
    SYSCALL_TRACE_GET_EVENTS = 4,
};

// 参数类型
typedef enum {
    PARAM_TYPE_LONG = 0,      // 整数参数
    PARAM_TYPE_POINTER,       // 指针地址
    PARAM_TYPE_STRING,        // 字符串内容
    PARAM_TYPE_FILENAME,      // 文件路径
} PARAM_TYPE;

// 系统调用参数
typedef struct _SYSCALL_PARAM {
    PARAM_TYPE type;
    char name[32];
    union {
        long value;           // 整数值
        unsigned long addr;   // 指针地址
        char string[256];     // 字符串数据
    } data;
} SYSCALL_PARAM, *PSYSCALL_PARAM;

// 系统调用事件基类
typedef struct _SYSCALL_EVENT_BASE {
    pid_t pid;
    uid_t uid;
    unsigned long timestamp;
    int syscall_nr;
    long retval;
    unsigned long duration;   // 执行时间(纳秒)
    int param_count;
    SYSCALL_PARAM params[6];  // 最多6个参数
} SYSCALL_EVENT_BASE, *PSYSCALL_EVENT_BASE;

// 特定系统调用事件结构
typedef struct _OPEN_EVENT {
    SYSCALL_EVENT_BASE base;
    char filename[PATH_MAX];
    int flags;
    mode_t mode;
} OPEN_EVENT, *POPEN_EVENT;

typedef struct _IO_EVENT {
    SYSCALL_EVENT_BASE base;
    int fd;
    size_t count;
    size_t actual;
} IO_EVENT, *PIO_EVENT;

// 系统调用追踪控制结构
typedef struct _SYSCALL_TRACE_CTL {
    pid_t target_pid;
    int action;            // see SYSCALL_TRACE_ACTION
    int filter_mask;       // 过滤掩码(暂时未使用)
    uintptr_t buffer;      // 用户空间缓冲区
    size_t buffer_size;    // 缓冲区大小
} SYSCALL_TRACE_CTL, *PSYSCALL_TRACE_CTL;

// 函数声明
int syscall_trace_init(void);
void syscall_trace_exit(void);
int handle_syscall_trace_control(PSYSCALL_TRACE_CTL ctl);
void trace_syscall_entry(int nr, unsigned long *args);
void trace_syscall_exit(long retval);

#endif // SYSCALL_TRACE_H
