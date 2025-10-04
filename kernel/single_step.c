#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <asm/debug-monitors.h>

#include "single_step.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/p_hook.h"
#include "version_control.h"

// --- State Management ---
static pid_t g_target_tid = 0;
static struct task_struct *g_target_task = NULL;
static struct pt_regs *g_last_regs = NULL;

// --- Synchronization ---
static DECLARE_WAIT_QUEUE_HEAD(g_step_wait_queue);
static bool g_step_completed = false;

// --- Helper to find task ---
static struct task_struct *find_task_by_tid(pid_t tid)
{
    struct pid *pid_struct = find_get_pid(tid);
    if (!pid_struct) return NULL;
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

// --- "Before" Hook for do_debug_exception ---
// Using hook_wrap, we intercept the call before the original function runs.
static void before_do_debug_exception(hook_fargs3_t *fargs, void *udata)
{
    unsigned int esr = (unsigned int)fargs->arg1;
    struct pt_regs *regs = (struct pt_regs *)fargs->arg2;
    struct task_struct *current_task = current;
    unsigned int exception_class = esr >> ESR_ELx_EC_SHIFT;

    // Check if it's a Software Step exception and if it's our target thread
    if (exception_class == ESR_ELx_EC_SOFTSTP_LOW && g_target_task && current_task->pid == g_target_tid) {
        PRINT_DEBUG("[single_step] Tid %d hit step trap.\n", g_target_tid);

        // 1. Tell hook_wrap to skip the original do_debug_exception call
        fargs->skip_origin = 1;
        fargs->ret = 0; // We must provide a return value for the skipped function

        // 2. Disable single-stepping to prevent immediate re-entry
        user_disable_single_step(current_task);
        
        // 3. Save the register state
        g_last_regs = regs;

        // 4. Wake up the user-space process waiting on g_step_wait_queue
        g_step_completed = true;
        wake_up_interruptible(&g_step_wait_queue);

        // 5. Put the thread to sleep, waiting for the next command from user-space
        set_current_state(TASK_INTERRUPTIBLE);
        schedule(); // Yield the CPU

        PRINT_DEBUG("[single_step] Tid %d woken up to continue.\n", g_target_tid);
    }
    // If it's not our target, we do nothing. hook_wrap will automatically call the original function.
}


// --- Control Logic (handle_single_step_control remains the same) ---
int handle_single_step_control(PSINGLE_STEP_CTL ctl)
{
    struct task_struct *task;

    if (ctl->action != STEP_ACTION_START && ctl->tid != g_target_tid) {
        return -EINVAL;
    }

    switch (ctl->action) {
        case STEP_ACTION_START:
            if (g_target_tid != 0) return -EBUSY;

            task = find_task_by_tid(ctl->tid);
            if (!task) return -ESRCH;

            g_target_tid = ctl->tid;
            g_target_task = task;
            PRINT_DEBUG("[single_step] Starting on TID %d.\n", g_target_tid);
            
            user_enable_single_step(g_target_task);
            break;

        case STEP_ACTION_STOP:
            if (!g_target_task) return -EINVAL;
            PRINT_DEBUG("[single_step] Stopping on TID %d.\n", g_target_tid);
            
            user_disable_single_step(g_target_task);
            
            wake_up_process(g_target_task);
            
            put_task_struct(g_target_task);
            g_target_tid = 0;
            g_target_task = NULL;
            g_last_regs = NULL;
            break;

        case STEP_ACTION_STEP:
            if (!g_target_task) return -EINVAL;
            PRINT_DEBUG("[single_step] Stepping TID %d.\n", g_target_tid);
            
            user_enable_single_step(g_target_task);
            wake_up_process(g_target_task);
            break;

        case STEP_ACTION_GET_INFO:
            if (!g_target_task) return -EINVAL;
            
            wait_event_interruptible(g_step_wait_queue, g_step_completed);
            
            if (g_last_regs) {
                if (copy_to_user((void __user *)ctl->regs_buffer, g_last_regs, sizeof(struct pt_regs))) {
                    g_step_completed = false;
                    return -EFAULT;
                }
            }
            g_step_completed = false;
            break;

        default:
            return -EINVAL;
    }
    return 0;
}


// --- Init and Exit ---
int single_step_init(void)
{
    void *addr = (void *)kallsyms_lookup_name("do_debug_exception");
    if (!addr) {
        PRINT_DEBUG("[-] single_step: Failed to find do_debug_exception.\n");
        return -1;
    }

    // Use hook_wrap for a 3-argument function.
    if (hook_wrap(addr, 3, before_do_debug_exception, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] single_step: Failed to wrap do_debug_exception().\n");
        return -1;
    }
    PRINT_DEBUG("[+] single_step: do_debug_exception() wrapped successfully.\n");
    return 0;
}

void single_step_exit(void)
{
    void *addr = (void *)kallsyms_lookup_name("do_debug_exception");
    if (addr) {
        hook_unwrap(addr, before_do_debug_exception, NULL);
        PRINT_DEBUG("[+] single_step: do_debug_exception() unwrapped.\n");
    }
    if (g_target_task) {
        user_disable_single_step(g_target_task);
        wake_up_process(g_target_task);
        put_task_struct(g_target_task);
        g_target_tid = 0;
        g_target_task = NULL;
    }
}
