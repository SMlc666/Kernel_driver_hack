#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <asm/debug-monitors.h>
#include <asm/tlbflush.h>

// Define PTE_TYPE_FAULT if not already defined
#ifndef PTE_TYPE_FAULT
#define PTE_TYPE_FAULT 0x0
#endif

#ifndef PTE_TYPE_MASK
#define PTE_TYPE_MASK 0x3  // Lowest 2 bits for type
#endif

#include "single_step.h"
#include "cvector.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/p_hook.h"
#include "version_control.h"
#include "mmu_breakpoint.h"

#ifdef CONFIG_SINGLE_STEP_MODE

// --- State Management ---
// For single-step debugger
pid_t g_target_tid = 0;
static struct task_struct *g_target_task = NULL;
struct user_pt_regs g_last_regs;
bool g_regs_valid = false;

// For multi-thread suspension
static cvector g_suspend_list = NULL;
static DEFINE_SPINLOCK(g_suspend_list_lock);

// --- Synchronization ---
static DECLARE_WAIT_QUEUE_HEAD(g_step_wait_queue);
static bool g_step_completed = false;

// --- Function Pointers for non-exported symbols ---
static void (*_user_enable_single_step)(struct task_struct *task);
static void (*_user_disable_single_step)(struct task_struct *task);

// --- Helper to find task ---
static struct task_struct *find_task_by_tid(pid_t tid)
{
    struct pid *pid_struct = find_get_pid(tid);
    if (!pid_struct) return NULL;
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

// --- Multi-thread suspend list management ---
void add_tid_to_suspend_list(pid_t tid)
{
    unsigned long flags;
    spin_lock_irqsave(&g_suspend_list_lock, flags);
    if (g_suspend_list) {
        cvector_pushback(g_suspend_list, &tid);
    }
    spin_unlock_irqrestore(&g_suspend_list_lock, flags);
}

void remove_tid_from_suspend_list(pid_t tid)
{
    unsigned long flags;
    citerator iter;
    pid_t current_tid;

    spin_lock_irqsave(&g_suspend_list_lock, flags);
    if (g_suspend_list) {
        for (iter = cvector_begin(g_suspend_list); iter != cvector_end(g_suspend_list); iter = cvector_next(g_suspend_list, iter)) {
            cvector_iter_val(g_suspend_list, iter, &current_tid);
            if (current_tid == tid) {
                cvector_rm(g_suspend_list, iter);
                break;
            }
        }
    }
    spin_unlock_irqrestore(&g_suspend_list_lock, flags);
}

bool is_tid_in_suspend_list(pid_t tid)
{
    unsigned long flags;
    citerator iter;
    pid_t current_tid;
    bool found = false;

    spin_lock_irqsave(&g_suspend_list_lock, flags);
    if (g_suspend_list) {
        for (iter = cvector_begin(g_suspend_list); iter != cvector_end(g_suspend_list); iter = cvector_next(g_suspend_list, iter)) {
            cvector_iter_val(g_suspend_list, iter, &current_tid);
            if (current_tid == tid) {
                found = true;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&g_suspend_list_lock, flags);
    return found;
}


// --- "Before" Hook for do_debug_exception ---
static void before_do_debug_exception(hook_fargs3_t *fargs, void *udata)
{
    unsigned int esr;
    struct pt_regs *regs;
    struct task_struct *current_task;
    unsigned int exception_class;
    pte_t *ptep;
    struct mmu_breakpoint *bp;

    esr = (unsigned int)fargs->arg1;
    regs = (struct pt_regs *)fargs->arg2;
    current_task = current;
    exception_class = esr >> ESR_ELx_EC_SHIFT;

    if (exception_class != ESR_ELx_EC_SOFTSTP_LOW) {
        return; // Not a software step exception, do nothing
    }

    // Case 1: It's a step for our single-step debugger
    if (g_target_task && current_task->pid == g_target_tid) {
        PRINT_DEBUG("[single_step] Tid %d hit step trap for debugger.\n", g_target_tid);

        fargs->skip_origin = 1;
        fargs->ret = 0;

        _user_disable_single_step(current_task);

        memcpy(&g_last_regs, regs, sizeof(struct user_pt_regs));
        g_regs_valid = true;

        g_step_completed = true;
        wake_up_interruptible(&g_step_wait_queue);

        set_current_state(TASK_INTERRUPTIBLE);
        schedule();

        PRINT_DEBUG("[single_step] Tid %d woken up to continue.\n", g_target_tid);
        return; // Handled
    }
    
    // Case 2: It's a step for our multi-thread suspension
    if (is_tid_in_suspend_list(current_task->pid)) {
        PRINT_DEBUG("[single_step] Tid %d hit step trap for multi-thread suspend.\n", current_task->pid);

        fargs->skip_origin = 1;
        fargs->ret = 0;

        _user_disable_single_step(current_task);
        
        // The thread is now suspended by sleeping
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
        
        return; // Handled
    }

    // Case 3: It's a step from an MMU breakpoint
    bp = find_breakpoint_by_pid(current_task->tgid, 0);
    if (bp) {
        PRINT_DEBUG("[single_step] MMU breakpoint step trap for TID %d.\n", current_task->pid);

        fargs->skip_origin = 1;
        fargs->ret = 0;

        _user_disable_single_step(current_task);

        ptep = virt_to_pte(bp->task, bp->addr);
        if (ptep && bp->vma) {
            pte_t current_pte = *ptep;
            if (pte_present(current_pte)) {
                pte_t new_pte = bp->original_pte;
                unsigned long new_state_bits = pte_val(current_pte) & (PTE_DIRTY | PTE_AF | PTE_WRITE);
                new_pte = __pte((pte_val(new_pte) & ~(PTE_DIRTY | PTE_AF | PTE_WRITE)) | new_state_bits);
                bp->original_pte = new_pte;
                new_pte = __pte(pte_val(new_pte) & ~PTE_TYPE_MASK);
                khack_set_pte_at(bp->task->mm, bp->addr, ptep, new_pte);
                flush_tlb_page(bp->vma, bp->addr);
                PRINT_DEBUG("[single_step] Re-armed MMU breakpoint for TID %d.\n", current_task->pid);
            } else {
                pte_t invalid_pte = __pte(pte_val(bp->original_pte) & ~PTE_TYPE_MASK);
                khack_set_pte_at(bp->task->mm, bp->addr, ptep, invalid_pte);
                flush_tlb_page(bp->vma, bp->addr);
                PRINT_DEBUG("[single_step] Page was swapped, restored invalid PTE for TID %d.\n", current_task->pid);
            }
        } else {
            PRINT_DEBUG("[single_step] Warning: Failed to get PTE or VMA for TID %d.\n", current_task->pid);
        }
        return; // Handled
    }
}


// --- Control Logic (handle_single_step_control remains the same) ---
int handle_single_step_control(PSINGLE_STEP_CTL ctl)
{
    struct task_struct *task;

    PRINT_DEBUG("[single_step] action=%d, ctl->tid=%d, g_target_tid=%d\n",
                ctl->action, ctl->tid, g_target_tid);

    if (ctl->action != STEP_ACTION_START && ctl->tid != g_target_tid) {
        PRINT_DEBUG("[single_step] ERROR: tid mismatch! ctl->tid=%d != g_target_tid=%d\n",
                    ctl->tid, g_target_tid);
        return -EINVAL;
    }

    switch (ctl->action) {
        case STEP_ACTION_START:
            if (g_target_tid != 0) return -EBUSY;

            task = find_task_by_tid(ctl->tid);
            if (!task) return -ESRCH;

            g_target_tid = ctl->tid;
            g_target_task = task;
            _user_enable_single_step(g_target_task);
            break;

        case STEP_ACTION_STOP:
            if (!g_target_task) return -EINVAL;
            PRINT_DEBUG("[single_step] Stopping on TID %d.\n", g_target_tid);
            
            _user_disable_single_step(g_target_task);
            
            wake_up_process(g_target_task);
            
            put_task_struct(g_target_task);
            g_target_tid = 0;
            g_target_task = NULL;
            g_regs_valid = false;
            break;

        case STEP_ACTION_STEP:
            if (!g_target_task) return -EINVAL;
            PRINT_DEBUG("[single_step] Stepping TID %d.\n", g_target_tid);
            
            _user_enable_single_step(g_target_task);
            wake_up_process(g_target_task);
            break;

        case STEP_ACTION_STEP_AND_WAIT:
            if (!g_target_task) return -EINVAL;
            PRINT_DEBUG("[single_step] Stepping and waiting on TID %d.\n", g_target_tid);

            _user_enable_single_step(g_target_task);
            wake_up_process(g_target_task);

            if (wait_event_interruptible(g_step_wait_queue, g_step_completed)) {
                return -ERESTARTSYS;
            }

            if (g_regs_valid) {
                if (copy_to_user((void __user *)ctl->regs_buffer, &g_last_regs, sizeof(g_last_regs))) {
                    g_step_completed = false;
                    return -EFAULT;
                }
            }
            g_step_completed = false;
            break;

        case STEP_ACTION_GET_INFO:
            if (!g_target_task) return -EINVAL;

            wait_event_interruptible(g_step_wait_queue, g_step_completed);

            if (g_regs_valid) {
                if (copy_to_user((void __user *)ctl->regs_buffer, &g_last_regs, sizeof(g_last_regs))) {
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
    void *addr;

    g_suspend_list = cvector_create(sizeof(pid_t));
    if (!g_suspend_list) {
        PRINT_DEBUG("[-] single_step: Failed to create suspend list.\n");
        return -ENOMEM;
    }

    _user_enable_single_step = (void (*)(struct task_struct *))kallsyms_lookup_name("user_enable_single_step");
    if (!_user_enable_single_step) {
        PRINT_DEBUG("[-] single_step: Failed to find user_enable_single_step.\n");
        return -1;
    }

    _user_disable_single_step = (void (*)(struct task_struct *))kallsyms_lookup_name("user_disable_single_step");
    if (!_user_disable_single_step) {
        PRINT_DEBUG("[-] single_step: Failed to find user_disable_single_step.\n");
        return -1;
    }

    addr = (void *)kallsyms_lookup_name("do_debug_exception");
    if (!addr) {
        PRINT_DEBUG("[-] single_step: Failed to find do_debug_exception.\n");
        return -1;
    }

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
        _user_disable_single_step(g_target_task);
        wake_up_process(g_target_task);
        put_task_struct(g_target_task);
        g_target_tid = 0;
        g_target_task = NULL;
    }
    
    // Clean up multi-thread suspend list
    if (g_suspend_list) {
        citerator iter;
        pid_t tid_to_wake;
        struct task_struct *task_to_wake;
        
        // Wake up any remaining suspended threads
        for (iter = cvector_begin(g_suspend_list); iter != cvector_end(g_suspend_list); iter = cvector_next(g_suspend_list, iter)) {
            cvector_iter_val(g_suspend_list, iter, &tid_to_wake);
            task_to_wake = find_task_by_tid(tid_to_wake);
            if (task_to_wake) {
                wake_up_process(task_to_wake);
                put_task_struct(task_to_wake);
            }
        }
        cvector_destroy(g_suspend_list);
        g_suspend_list = NULL;
    }
}
#endif
