#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h> // For set_task_state and wake_up_process
#include <linux/uaccess.h>
#include "thread.h"
#include "version_control.h"

// The one and only implementation for thread control, using the stealthiest methods.
int handle_thread_control(PTHREAD_CTL ctl)
{
    struct task_struct *task;
    int ret = 0;

    rcu_read_lock();
    task = find_task_by_vpid(ctl->tid);
    if (task) {
        get_task_struct(task); // Pin the task struct
    }
    rcu_read_unlock();

    if (!task) {
        return -ESRCH; // No such thread
    }

    switch (ctl->action) {
        case THREAD_ACTION_SUSPEND:
            PRINT_DEBUG("[+] Stealth Suspend: Setting TID %d to TASK_UNINTERRUPTIBLE.\n", ctl->tid);
            // Directly manipulate the scheduler state. No signals involved.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
            task->__state = TASK_UNINTERRUPTIBLE;
#else
            task->state = TASK_UNINTERRUPTIBLE;
#endif
            break;

        case THREAD_ACTION_RESUME:
            PRINT_DEBUG("[+] Stealth Resume: Waking up TID %d.\n", ctl->tid);
            // Use the kernel's standard wakeup function. This correctly sets the
            // state to TASK_RUNNING and places it on the runqueue. No signals.
            ret = wake_up_process(task);
            // wake_up_process returns 1 on success (if the task was woken), 0 otherwise.
            // We can normalize this to 0 for success for our ioctl.
            ret = (ret == 1) ? 0 : -EAGAIN;
            break;

        case THREAD_ACTION_KILL:
            PRINT_DEBUG("[+] Terminate: Using safe kernel mechanism (SIGKILL) for TID %d.\n", ctl->tid);
            // This is a deliberate design choice. Bypassing the kernel's safe
            // exit path is extremely dangerous and risks kernel panic.
            // Using send_sig_info is the only reliable way to terminate a task.
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
    size_t buffer_capacity = et->count; // This is safe, et is a kernel copy
    int ret = 0;
    PTHREAD_INFO user_buffer = (PTHREAD_INFO)et->buffer; // This is a user-space pointer

    rcu_read_lock();
    process_leader = find_task_by_vpid(et->pid);
    if (!process_leader) {
        rcu_read_unlock();
        return -ESRCH;
    }

    for_each_thread(process_leader, thread) {
        if (threads_found < buffer_capacity) {
            THREAD_INFO info;
            info.tid = thread->pid;
            strncpy(info.name, thread->comm, sizeof(info.name) - 1);
            info.name[sizeof(info.name) - 1] = '\0';

            // The destination is a user-space buffer
            if (copy_to_user(&user_buffer[threads_found], &info, sizeof(THREAD_INFO))) {
                ret = -EFAULT;
                break;
            }
        }
        threads_found++;
    }
    rcu_read_unlock();

    if (ret == 0) {
        // The caller (dispatch_ioctl) will copy the updated count back
        et->count = threads_found;
    }

    return ret;
}
