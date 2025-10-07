#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>

#include "syscall_trace.h"
#include "cvector.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/p_hook.h"
#include "version_control.h"

// 全局状态
static bool g_trace_enabled = false;
static pid_t g_target_pid = 0;
static cvector g_event_buffer = NULL;
static DEFINE_SPINLOCK(g_trace_lock);
static unsigned long **g_sys_call_table = NULL;

// 时间统计
static unsigned long g_entry_time = 0;

// Hook函数指针
static asmlinkage long (*original_syscalls[NR_syscalls])(const struct pt_regs *);

// 函数声明
static void parse_open_params(unsigned long *args, PSYSCALL_EVENT_BASE event);
static void parse_io_params(unsigned long *args, PSYSCALL_EVENT_BASE event);
static void parse_generic_params(unsigned long *args, PSYSCALL_EVENT_BASE event);
static int copy_string_from_user_safe(const char __user *user_ptr, char *kernel_buffer, size_t max_len);

// 系统调用Hook包装函数
#define DEFINE_SYSCALL_HOOK(nr, name) \
static asmlinkage long hooked_##name(const struct pt_regs *regs) \
{ \
    long retval; \
    unsigned long args[6] = {regs->regs[0], regs->regs[1], regs->regs[2], \
                           regs->regs[3], regs->regs[4], regs->regs[5]}; \
    \
    if (g_trace_enabled && (g_target_pid == 0 || g_target_pid == current->pid)) { \
        trace_syscall_entry(nr, args); \
    } \
    \
    retval = original_syscalls[nr](regs); \
    \
    if (g_trace_enabled && (g_target_pid == 0 || g_target_pid == current->pid)) { \
        trace_syscall_exit(retval); \
    } \
    \
    return retval; \
}

// 定义常用的系统调用Hook
DEFINE_SYSCALL_HOOK(__NR_open, sys_open)
DEFINE_SYSCALL_HOOK(__NR_openat, sys_openat)
DEFINE_SYSCALL_HOOK(__NR_close, sys_close)
DEFINE_SYSCALL_HOOK(__NR_read, sys_read)
DEFINE_SYSCALL_HOOK(__NR_write, sys_write)
DEFINE_SYSCALL_HOOK(__NR_execve, sys_execve)
DEFINE_SYSCALL_HOOK(__NR_mmap, sys_mmap)
DEFINE_SYSCALL_HOOK(__NR_mprotect, sys_mprotect)
DEFINE_SYSCALL_HOOK(__NR_clone, sys_clone)

// 安全地从用户空间复制字符串
static int copy_string_from_user_safe(const char __user *user_ptr, char *kernel_buffer, size_t max_len)
{
    long copied;

    if (!user_ptr || !kernel_buffer || max_len == 0) {
        return -EINVAL;
    }
    
    // 清零缓冲区
    memset(kernel_buffer, 0, max_len);
    
    // 使用strncpy_from_user安全复制
    copied = strncpy_from_user(kernel_buffer, user_ptr, max_len - 1);
    if (copied < 0) {
        return copied; // 返回错误码
    }
    
    kernel_buffer[max_len - 1] = '\0'; // 确保null终止
    return 0;
}

// 解析open系统调用参数
static void parse_open_params(unsigned long *args, PSYSCALL_EVENT_BASE event)
{
    event->param_count = 3;
    
    // 参数1: filename
    strncpy(event->params[0].name, "filename", sizeof(event->params[0].name) - 1);
    event->params[0].type = PARAM_TYPE_FILENAME;
    if (copy_string_from_user_safe((const char __user *)args[0], 
                                  event->params[0].data.string, 
                                  sizeof(event->params[0].data.string)) != 0) {
        strncpy(event->params[0].data.string, "<invalid>", sizeof(event->params[0].data.string) - 1);
    }
    
    // 参数2: flags
    strncpy(event->params[1].name, "flags", sizeof(event->params[1].name) - 1);
    event->params[1].type = PARAM_TYPE_LONG;
    event->params[1].data.value = (long)args[1];
    
    // 参数3: mode
    strncpy(event->params[2].name, "mode", sizeof(event->params[2].name) - 1);
    event->params[2].type = PARAM_TYPE_LONG;
    event->params[2].data.value = (long)args[2];
}

// 解析IO系统调用参数
static void parse_io_params(unsigned long *args, PSYSCALL_EVENT_BASE event)
{
    event->param_count = 3;
    
    // 参数1: fd
    strncpy(event->params[0].name, "fd", sizeof(event->params[0].name) - 1);
    event->params[0].type = PARAM_TYPE_LONG;
    event->params[0].data.value = (long)args[0];
    
    // 参数2: buf (指针)
    strncpy(event->params[1].name, "buf", sizeof(event->params[1].name) - 1);
    event->params[1].type = PARAM_TYPE_POINTER;
    event->params[1].data.addr = args[1];
    
    // 参数3: count
    strncpy(event->params[2].name, "count", sizeof(event->params[2].name) - 1);
    event->params[2].type = PARAM_TYPE_LONG;
    event->params[2].data.value = (long)args[2];
}

// 解析通用参数
static void parse_generic_params(unsigned long *args, PSYSCALL_EVENT_BASE event)
{
    // 默认处理前3个参数为整数
    int param_count = 3;
    int i;
    for (i = 0; i < param_count && i < 6; i++) {
        snprintf(event->params[i].name, sizeof(event->params[i].name) - 1, "arg%d", i);
        event->params[i].type = PARAM_TYPE_LONG;
        event->params[i].data.value = (long)args[i];
    }
    event->param_count = param_count;
}

// 系统调用入口追踪
void trace_syscall_entry(int nr, unsigned long *args)
{
    unsigned long flags;
    struct timespec64 ts;
    
    spin_lock_irqsave(&g_trace_lock, flags);
    
    // 记录入口时间
    ktime_get_real_ts64(&ts);
    g_entry_time = ts.tv_sec * 1000000000UL + ts.tv_nsec;
    
    spin_unlock_irqrestore(&g_trace_lock, flags);
}

// 系统调用出口追踪
void trace_syscall_exit(long retval)
{
    unsigned long flags;
    SYSCALL_EVENT_BASE *event;
    struct timespec64 ts;
    unsigned long exit_time;
    unsigned long duration;
    
    spin_lock_irqsave(&g_trace_lock, flags);
    
    if (!g_event_buffer) {
        spin_unlock_irqrestore(&g_trace_lock, flags);
        return;
    }
    
    // 计算执行时间
    ktime_get_real_ts64(&ts);
    exit_time = ts.tv_sec * 1000000000UL + ts.tv_nsec;
    duration = exit_time - g_entry_time;
    
    // 创建事件
    event = kmalloc(sizeof(SYSCALL_EVENT_BASE), GFP_ATOMIC);
    if (!event) {
        spin_unlock_irqrestore(&g_trace_lock, flags);
        return;
    }
    
    // 填充事件基本信息
    event->pid = current->pid;
    event->uid = current_uid().val;
    event->timestamp = exit_time;
    event->syscall_nr = 0; // 这里需要从上下文获取
    event->retval = retval;
    event->duration = duration;
    event->param_count = 0;
    
    // TODO: 根据系统调用号解析具体参数
    // 这需要保存系统调用号到上下文
    
    // 添加到事件缓冲区
    if (cvector_pushback(g_event_buffer, &event) != CVESUCCESS) {
        kfree(event);
    }
    
    spin_unlock_irqrestore(&g_trace_lock, flags);
}

// 处理系统调用追踪控制
int handle_syscall_trace_control(PSYSCALL_TRACE_CTL ctl)
{
    unsigned long flags;
    int ret = 0;
    
    spin_lock_irqsave(&g_trace_lock, flags);
    
    switch (ctl->action) {
        case SYSCALL_TRACE_START:
            if (g_trace_enabled) {
                ret = -EBUSY;
                break;
            }
            g_target_pid = ctl->target_pid;
            g_trace_enabled = true;
            PRINT_DEBUG("[syscall_trace] Started tracing PID %d\n", ctl->target_pid);
            break;
            
        case SYSCALL_TRACE_STOP:
            if (!g_trace_enabled) {
                ret = -EINVAL;
                break;
            }
            g_trace_enabled = false;
            g_target_pid = 0;
            PRINT_DEBUG("[syscall_trace] Stopped tracing\n");
            break;
            
        case SYSCALL_TRACE_CLEAR:
            if (g_event_buffer) {
                // 清空事件缓冲区
                while (cvector_length(g_event_buffer) > 0) {
                    SYSCALL_EVENT_BASE *event;
                    if (cvector_popback(g_event_buffer, &event) == CVESUCCESS) {
                        kfree(event);
                    }
                }
                PRINT_DEBUG("[syscall_trace] Cleared event buffer\n");
            }
            break;
            
        case SYSCALL_TRACE_GET_EVENTS:
            // TODO: 实现事件获取逻辑
            ret = -ENOSYS;
            break;
            
        default:
            ret = -EINVAL;
            break;
    }
    
    spin_unlock_irqrestore(&g_trace_lock, flags);
    return ret;
}

// 初始化系统调用追踪
int syscall_trace_init(void)
{
    PRINT_DEBUG("[syscall_trace] Initializing\n");
    
    // 创建事件缓冲区
    g_event_buffer = cvector_create(sizeof(SYSCALL_EVENT_BASE *));
    if (!g_event_buffer) {
        PRINT_DEBUG("[-] syscall_trace: Failed to create event buffer\n");
        return -ENOMEM;
    }
    
    // 获取系统调用表
    g_sys_call_table = (unsigned long **)get_sys_call_table();
    if (!g_sys_call_table) {
        PRINT_DEBUG("[-] syscall_trace: Failed to get sys_call_table\n");
        cvector_destroy(g_event_buffer);
        g_event_buffer = NULL;
        return -EFAULT;
    }
    
    PRINT_DEBUG("[+] syscall_trace: Initialized successfully\n");
    return 0;
}

// 退出系统调用追踪
void syscall_trace_exit(void)
{
    unsigned long flags;
    
    spin_lock_irqsave(&g_trace_lock, flags);
    
    // 停止追踪
    g_trace_enabled = false;
    g_target_pid = 0;
    
    // 清理事件缓冲区
    if (g_event_buffer) {
        while (cvector_length(g_event_buffer) > 0) {
            SYSCALL_EVENT_BASE *event;
            if (cvector_popback(g_event_buffer, &event) == CVESUCCESS) {
                kfree(event);
            }
        }
        cvector_destroy(g_event_buffer);
        g_event_buffer = NULL;
    }
    
    spin_unlock_irqrestore(&g_trace_lock, flags);
    
    PRINT_DEBUG("[+] syscall_trace: Exited\n");
}
