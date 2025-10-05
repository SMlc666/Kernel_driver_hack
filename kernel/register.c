#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <asm/processor.h>

#include "register.h"
#include "single_step.h"
#include "version_control.h"

// 外部变量声明
extern pid_t g_target_tid;
extern struct user_pt_regs g_last_regs;
extern bool g_regs_valid;

// 检查任务是否处于暂停状态
static bool is_task_suspended(struct task_struct *task)
{
    // 检查单步调试状态
    if (task->pid == g_target_tid && g_regs_valid) {
        return true;
    }
    
    // 检查各种暂停状态
    return task_is_stopped(task) ||      // SIGSTOP等信号停止
           task_is_traced(task) ||       // ptrace跟踪
           task->state == TASK_UNINTERRUPTIBLE;  // 线程控制暂停
}

// 查找任务并增加引用计数
static struct task_struct *find_and_get_task(pid_t pid)
{
    struct task_struct *task;
    struct pid *pid_struct;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return NULL;
    }
    
    return task;
}

// 从内核栈获取寄存器
static int get_regs_from_stack(struct task_struct *task, struct user_pt_regs *user_regs)
{
    struct pt_regs *kernel_regs;
    
    // 获取任务的寄存器
    kernel_regs = task_pt_regs(task);
    if (!kernel_regs) {
        PRINT_DEBUG("[-] register: Failed to get pt_regs from task stack\n");
        return -EFAULT;
    }
    
    // 复制寄存器数据
    memcpy(user_regs, kernel_regs, sizeof(struct user_pt_regs));
    
    PRINT_DEBUG("[+] register: Successfully got regs from stack for PID %d\n", task->pid);
    return 0;
}

// 将寄存器写入内核栈
static int set_regs_to_stack(struct task_struct *task, struct user_pt_regs *user_regs)
{
    struct pt_regs *kernel_regs;
    
    // 获取任务的寄存器位置
    kernel_regs = task_pt_regs(task);
    if (!kernel_regs) {
        PRINT_DEBUG("[-] register: Failed to get pt_regs from task stack for writing\n");
        return -EFAULT;
    }
    
    // 写入寄存器数据
    memcpy(kernel_regs, user_regs, sizeof(struct user_pt_regs));
    
    PRINT_DEBUG("[+] register: Successfully set regs to stack for PID %d\n", task->pid);
    return 0;
}

// 主要的寄存器访问处理函数
int handle_register_access(PREG_ACCESS reg_access)
{
    struct task_struct *task;
    struct user_pt_regs temp_regs;
    int ret = 0;
    
    PRINT_DEBUG("[+] register: PID=%d, operation=%d, buffer=0x%lx\n", 
                reg_access->target_pid, reg_access->operation, reg_access->regs_buffer);
    
    // 查找目标线程
    task = find_and_get_task(reg_access->target_pid);
    if (!task) {
        PRINT_DEBUG("[-] register: Task %d not found\n", reg_access->target_pid);
        return -ESRCH;
    }
    
    // 检查线程是否真的暂停了
    if (!is_task_suspended(task)) {
        PRINT_DEBUG("[-] register: Task %d is not suspended\n", reg_access->target_pid);
        put_task_struct(task);
        return -EINVAL;
    }
    
    if (reg_access->operation == 0) {
        // 读取寄存器
        PRINT_DEBUG("[+] register: Reading registers for PID %d\n", reg_access->target_pid);
        
        if (reg_access->target_pid == g_target_tid && g_regs_valid) {
            // 单步调试模式：直接使用已保存的寄存器
            PRINT_DEBUG("[+] register: Using single-step saved registers\n");
            temp_regs = g_last_regs;
        } else {
            // 其他暂停模式：从内核栈获取寄存器
            ret = get_regs_from_stack(task, &temp_regs);
            if (ret != 0) {
                put_task_struct(task);
                return ret;
            }
        }
        
        // 复制到用户空间
        if (copy_to_user((void __user *)reg_access->regs_buffer, 
                        &temp_regs, sizeof(temp_regs))) {
            PRINT_DEBUG("[-] register: Failed to copy registers to user space\n");
            put_task_struct(task);
            return -EFAULT;
        }
        
        PRINT_DEBUG("[+] register: Successfully copied %zu bytes to user space\n", sizeof(temp_regs));
        
    } else {
        // 写入寄存器
        PRINT_DEBUG("[+] register: Writing registers for PID %d\n", reg_access->target_pid);
        
        // 从用户空间复制寄存器数据
        if (copy_from_user(&temp_regs, 
                          (void __user *)reg_access->regs_buffer, 
                          sizeof(temp_regs))) {
            PRINT_DEBUG("[-] register: Failed to copy registers from user space\n");
            put_task_struct(task);
            return -EFAULT;
        }
        
        if (reg_access->target_pid == g_target_tid && g_regs_valid) {
            // 单步调试模式：修改g_last_regs
            PRINT_DEBUG("[+] register: Updating single-step saved registers\n");
            g_last_regs = temp_regs;
            
            // 同时更新内核栈中的寄存器
            ret = set_regs_to_stack(task, &temp_regs);
            if (ret != 0) {
                put_task_struct(task);
                return ret;
            }
        } else {
            // 其他暂停模式：直接修改内核栈中的寄存器
            ret = set_regs_to_stack(task, &temp_regs);
            if (ret != 0) {
                put_task_struct(task);
                return ret;
            }
        }
        
        PRINT_DEBUG("[+] register: Successfully updated registers for PID %d\n", reg_access->target_pid);
    }
    
    put_task_struct(task);
    PRINT_DEBUG("[+] register: Operation completed successfully\n");
    return 0;
}
