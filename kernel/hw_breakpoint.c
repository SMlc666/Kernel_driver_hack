#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched/signal.h>

#include "hw_breakpoint.h"
#include "cvector.h"

#ifdef CONFIG_HW_BREAKPOINT_MODE
// Internal implementation of hw_breakpoint_init to avoid kernel symbol conflicts
int khack_hw_breakpoint_init(struct perf_event_attr *attr)
{
    // Initialize the perf_event_attr structure for hardware breakpoint
    perf_event_attr__init(&attr);
    
    attr->type = PERF_TYPE_BREAKPOINT;
    attr->size = sizeof(struct perf_event_attr);
    attr->pinned = 1;
    attr->disabled = 1;
    attr->exclude_kernel = 1;
    attr->exclude_hv = 1;
    attr->bp_state = 1;
    attr->bp_len = HW_BREAKPOINT_LEN_8;
    
    return 0;
}
// Internal struct to track our breakpoints
struct khack_hw_breakpoint {
    struct list_head list;
    struct perf_event *bp_event;
    pid_t tgid;
    pid_t pid; // Thread ID
    uintptr_t addr;
};

// Global list for our installed breakpoints
static LIST_HEAD(g_hw_breakpoints);
static DEFINE_MUTEX(g_hw_bp_mutex);

// Global buffer for hit events
static cvector g_hit_buffer = NULL;
static DEFINE_SPINLOCK(g_hit_buffer_lock);

// Forward declarations
static void breakpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);

static int add_hw_breakpoint(PHW_BREAKPOINT_CTL ctl) {
    struct task_struct *task;
    struct perf_event_attr attr;
    struct perf_event *bp_event;
    struct khack_hw_breakpoint *khack_bp;

    task = get_pid_task(find_vpid(ctl->pid), PIDTYPE_PID);
    if (!task) {
        return -ESRCH;
    }

    khack_hw_breakpoint_init(&attr);
    attr.bp_addr = ctl->addr;
    attr.bp_len = ctl->len;
    if (ctl->type == HW_BP_TYPE_EXECUTE) {
        attr.bp_type = HW_BREAKPOINT_X;
    } else if (ctl->type == HW_BP_TYPE_WRITE) {
        attr.bp_type = HW_BREAKPOINT_W;
    } else if (ctl->type == HW_BP_TYPE_RW) {
        attr.bp_type = HW_BREAKPOINT_RW;
    } else {
        put_task_struct(task);
        return -EINVAL;
    }

    khack_bp = kmalloc(sizeof(*khack_bp), GFP_KERNEL);
    if (!khack_bp) {
        put_task_struct(task);
        return -ENOMEM;
    }

    bp_event = register_wide_hw_breakpoint(&attr, breakpoint_handler, task);
    if (IS_ERR_OR_NULL(bp_event)) {
        kfree(khack_bp);
        put_task_struct(task);
        return PTR_ERR(bp_event);
    }

    khack_bp->bp_event = bp_event;
    khack_bp->tgid = task->tgid;
    khack_bp->pid = task->pid;
    khack_bp->addr = ctl->addr;

    mutex_lock(&g_hw_bp_mutex);
    list_add_tail(&khack_bp->list, &g_hw_breakpoints);
    mutex_unlock(&g_hw_bp_mutex);

    put_task_struct(task);
    PRINT_DEBUG("[+] hw_bp: Added breakpoint for PID %d at 0x%lx\n", ctl->pid, ctl->addr);
    return 0;
}

static int remove_hw_breakpoint(PHW_BREAKPOINT_CTL ctl) {
    struct khack_hw_breakpoint *khack_bp, *tmp;
    bool found = false;

    mutex_lock(&g_hw_bp_mutex);
    list_for_each_entry_safe(khack_bp, tmp, &g_hw_breakpoints, list) {
        if (khack_bp->pid == ctl->pid && khack_bp->addr == ctl->addr) {
            unregister_hw_breakpoint(khack_bp->bp_event);
            list_del(&khack_bp->list);
            kfree(khack_bp);
            found = true;
            break;
        }
    }
    mutex_unlock(&g_hw_bp_mutex);

    if (found) {
        PRINT_DEBUG("[+] hw_bp: Removed breakpoint for PID %d at 0x%lx\n", ctl->pid, ctl->addr);
        return 0;
    } else {
        return -ENOENT;
    }
}

static void breakpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    unsigned long flags;
    HW_BREAKPOINT_HIT_INFO *hit_info;

    hit_info = kmalloc(sizeof(*hit_info), GFP_ATOMIC);
    if (!hit_info) {
        return;
    }

    hit_info->pid = current->pid;
    hit_info->timestamp = ktime_get_ns();
    hit_info->addr = instruction_pointer(regs);
    memcpy(&hit_info->regs, regs, sizeof(struct user_pt_regs));

    spin_lock_irqsave(&g_hit_buffer_lock, flags);
    if (g_hit_buffer) {
        if (cvector_pushback(g_hit_buffer, &hit_info) != CVESUCCESS) {
            kfree(hit_info);
        }
    } else {
        kfree(hit_info);
    }
    spin_unlock_irqrestore(&g_hit_buffer_lock, flags);
}

int handle_hw_breakpoint_control(PHW_BREAKPOINT_CTL ctl) {
    switch (ctl->action) {
        case HW_BP_ADD:
            return add_hw_breakpoint(ctl);
        case HW_BP_REMOVE:
            return remove_hw_breakpoint(ctl);
        default:
            return -EINVAL;
    }
}

int handle_hw_breakpoint_get_hits(PHW_BREAKPOINT_GET_HITS_CTL ctl, unsigned long arg) {
    unsigned long flags;
    size_t hits_to_copy, i;
    int ret = 0;

    spin_lock_irqsave(&g_hit_buffer_lock, flags);
    if (!g_hit_buffer) {
        spin_unlock_irqrestore(&g_hit_buffer_lock, flags);
        return -EINVAL;
    }

    hits_to_copy = cvector_length(g_hit_buffer);
    if (ctl->count < hits_to_copy) {
        hits_to_copy = ctl->count;
    }

    for (i = 0; i < hits_to_copy; ++i) {
        HW_BREAKPOINT_HIT_INFO *info;
        cvector_val_at(g_hit_buffer, i, &info);
        if (copy_to_user(&((PHW_BREAKPOINT_HIT_INFO)ctl->buffer)[i], info, sizeof(HW_BREAKPOINT_HIT_INFO))) {
            ret = -EFAULT;
            // Don't clear buffer on partial copy failure
            goto out;
        }
    }

    // Clear the buffer after successful copy
    for (i = 0; i < cvector_length(g_hit_buffer); ++i) {
        HW_BREAKPOINT_HIT_INFO *info;
        cvector_val_at(g_hit_buffer, i, &info);
        kfree(info);
    }
    cvector_destroy(g_hit_buffer);
    g_hit_buffer = cvector_create(sizeof(HW_BREAKPOINT_HIT_INFO *));

    ctl->count = hits_to_copy;
    if (copy_to_user((void __user *)arg, ctl, sizeof(*ctl))) {
        ret = -EFAULT;
    }

out:
    spin_unlock_irqrestore(&g_hit_buffer_lock, flags);
    return ret;
}

int hw_breakpoint_init(void) {
    unsigned long flags;
    spin_lock_irqsave(&g_hit_buffer_lock, flags);
    if (!g_hit_buffer) {
        g_hit_buffer = cvector_create(sizeof(HW_BREAKPOINT_HIT_INFO *));
    }
    spin_unlock_irqrestore(&g_hit_buffer_lock, flags);
    if (!g_hit_buffer) {
        return -ENOMEM;
    }
    PRINT_DEBUG("[+] hw_bp: Module initialized.\n");
    return 0;
}

void hw_breakpoint_exit(void) {
    struct khack_hw_breakpoint *khack_bp, *tmp;
    unsigned long flags;

    mutex_lock(&g_hw_bp_mutex);
    list_for_each_entry_safe(khack_bp, tmp, &g_hw_breakpoints, list) {
        unregister_hw_breakpoint(khack_bp->bp_event);
        list_del(&khack_bp->list);
        kfree(khack_bp);
    }
    mutex_unlock(&g_hw_bp_mutex);

    spin_lock_irqsave(&g_hit_buffer_lock, flags);
    if (g_hit_buffer) {
        size_t i;
        for (i = 0; i < cvector_length(g_hit_buffer); ++i) {
            HW_BREAKPOINT_HIT_INFO *info;
            cvector_val_at(g_hit_buffer, i, &info);
            kfree(info);
        }
        cvector_destroy(g_hit_buffer);
        g_hit_buffer = NULL;
    }
    spin_unlock_irqrestore(&g_hit_buffer_lock, flags);
    PRINT_DEBUG("[+] hw_bp: Module exited and cleaned up.\n");
}

#endif // CONFIG_HW_BREAKPOINT_MODE
