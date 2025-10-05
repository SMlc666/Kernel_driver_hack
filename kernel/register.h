#ifndef REGISTER_H
#define REGISTER_H

#include <linux/types.h>
#include <linux/sched.h>

// 寄存器操作结构
typedef struct _REG_ACCESS {
    pid_t target_pid;           // 目标线程PID
    uintptr_t regs_buffer;      // user_pt_regs缓冲区地址
    int operation;              // 0=读取寄存器, 1=写入寄存器
} REG_ACCESS, *PREG_ACCESS;

// 寄存器操作函数
int handle_register_access(PREG_ACCESS reg_access);

#endif // REGISTER_H
