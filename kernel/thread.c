#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h> // For set_task_state and wake_up_process
#include <linux/uaccess.h>
#include <linux/pid_namespace.h> // For task_active_pid_ns
#include <linux/slab.h> // For kmalloc/kfree
#include <linux/kallsyms.h> // For kallsyms_lookup_name
#include "thread.h"
#include "single_step.h"
#include "version_control.h"

// Function pointer for single-step functions
static void (*_user_enable_single_step)(struct task_struct *task);

#ifdef CONFIG_THREAD_CONTROL_MODE

// The function find_task_by_vpid is not exported in all kernel versions.
// We re-implement it here using exported functions.
static struct task_struct *khack_find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns)
{
    RCU_LOCKDEP_WARN(!rcu_read_lock_held(), "khack_find_task_by_pid_ns() needs rcu_read_lock() protection");
    return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
}

static struct task_struct *khack_find_task_by_vpid(pid_t vnr)
{
    return khack_find_task_by_pid_ns(vnr, task_active_pid_ns(current));
}

// The one and only implementation for thread control, using the stealthiest methods.
int handle_thread_control(PTHREAD_CTL ctl)
{
    struct task_struct *task;
    int ret = 0;

    // Initialize function pointer if needed
    if (!_user_enable_single_step) {
        _user_enable_single_step = (void (*)(struct task_struct *))kallsyms_lookup_name("user_enable_single_step");
        if (!_user_enable_single_step) {
            PRINT_DEBUG("[-] thread: Failed to find user_enable_single_step.\n");
            return -EFAULT;
        }
    }

    rcu_read_lock();
    task = khack_find_task_by_vpid(ctl->tid);
    if (task) {
        get_task_struct(task); // Pin the task struct
    }
    rcu_read_unlock();

    if (!task) {
        return -ESRCH; // No such thread
    }

    switch (ctl->action) {
        case THREAD_ACTION_SUSPEND:
            PRINT_DEBUG("[+] Stealth Suspend: Using single-step mechanism for TID %d.\n", ctl->tid);
            add_tid_to_suspend_list(ctl->tid);
            _user_enable_single_step(task);
            break;

        case THREAD_ACTION_RESUME:
            PRINT_DEBUG("[+] Stealth Resume: Waking up TID %d.\n", ctl->tid);
            remove_tid_from_suspend_list(ctl->tid);
            ret = wake_up_process(task);
            ret = (ret == 1) ? 0 : -EAGAIN;
            break;

        case THREAD_ACTION_KILL:
            PRINT_DEBUG("[+] Terminate: Using safe kernel mechanism (SIGKILL) for TID %d.\n", ctl->tid);
            ret = send_sig_info(SIGKILL, SEND_SIG_FORCED, task);
            break;

        default:
            ret = -EINVAL; // Invalid action
            break;
    }

    put_task_struct(task); // Unpin the task struct
    return ret;
}

int handle_enum_threads(PENUM_THREADS et)
{
    struct task_struct *process_leader, *thread;
    size_t threads_found = 0;
    size_t buffer_capacity = et->count;
    int ret = 0;
    PTHREAD_INFO user_buffer = (PTHREAD_INFO)et->buffer;
    THREAD_INFO *kernel_buffer = NULL;

    // Allocate kernel buffer to avoid copy_to_user in RCU critical section
    kernel_buffer = kmalloc(buffer_capacity * sizeof(THREAD_INFO), GFP_KERNEL);
    if (!kernel_buffer && buffer_capacity > 0) {
        return -ENOMEM;
    }

    rcu_read_lock();
    process_leader = khack_find_task_by_vpid(et->pid);
    if (!process_leader) {
        rcu_read_unlock();
        kfree(kernel_buffer);
        return -ESRCH;
    }

    // Collect thread info in kernel buffer while holding RCU lock
    for_each_thread(process_leader, thread) {
        if (threads_found < buffer_capacity) {
            kernel_buffer[threads_found].tid = thread->pid;
            strncpy(kernel_buffer[threads_found].name, thread->comm, sizeof(kernel_buffer[threads_found].name) - 1);
            kernel_buffer[threads_found].name[sizeof(kernel_buffer[threads_found].name) - 1] = '\0';
        }
        threads_found++;
    }
    rcu_read_unlock();

    // Now copy to user space without holding any locks
    if (threads_found > 0 && buffer_capacity > 0) {
        size_t copy_count = (threads_found < buffer_capacity) ? threads_found : buffer_capacity;
        if (copy_to_user(user_buffer, kernel_buffer, copy_count * sizeof(THREAD_INFO))) {
            ret = -EFAULT;
        }
    }

    kfree(kernel_buffer);

    if (ret == 0) {
        et->count = threads_found;
    }

    return ret;
}
#endif
