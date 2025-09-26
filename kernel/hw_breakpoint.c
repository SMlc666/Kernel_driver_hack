#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h> //kmalloc与kfree
#include <asm/compat.h>
#include <linux/uaccess.h>

#include "hw_breakpoint.h"
#include "arm64_register_helper.h"
#include "api_proxy.h"
#include "anti_ptrace_detection.h"
#include "version_control.h"
#include "process.h"

// --- Globals ---
static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr = NULL;
static atomic64_t g_hook_pc;

// --- Forward Declarations ---
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);
static void clean_all_hwbp(void);

// --- Stack Walking ---
static int walk_user_stack(struct pt_regs *regs, uint64_t *trace_buffer, int max_frames)
{
    uint64_t fp, sp;
    int frame_count = 0;
    struct mm_struct *mm = current->mm;

    if (!trace_buffer || !regs || !mm) {
        return 0;
    }

    fp = regs->regs[29];
    sp = regs->sp;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

    while (frame_count < max_frames) {
        uint64_t next_fp, return_addr;

        // Basic validation
        if (fp < sp || fp & 0x7 || !access_ok(VERIFY_READ, (void __user *)fp, 16)) {
            break;
        }

        if (get_user(next_fp, (uint64_t __user *)fp) != 0) {
            break;
        }

        if (get_user(return_addr, (uint64_t __user *)(fp + 8)) != 0) {
            break;
        }

        trace_buffer[frame_count++] = return_addr;

        if (next_fp == fp) { // Avoid infinite loops
            break;
        }
        fp = next_fp;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    return frame_count;
}


// --- Breakpoint Logic ---
static void record_hit_details(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs) {
    struct HWBP_HIT_ITEM hit_item = {0};
	if (!info || !regs) {
        return;
    }
	
    hit_item.task_id = info->task_id;
    hit_item.hit_addr = regs->pc;
	hit_item.hit_time = ktime_get_real_seconds();
    
    memcpy(&hit_item.regs_info.regs, regs->regs, sizeof(hit_item.regs_info.regs));
    hit_item.regs_info.sp = regs->sp;
    hit_item.regs_info.pc = regs->pc;
    hit_item.regs_info.pstate = regs->pstate;
    hit_item.regs_info.orig_x0 = regs->orig_x0;
    hit_item.regs_info.syscallno = regs->syscallno;

    // Walk the stack
    hit_item.stack_trace_size = walk_user_stack(regs, hit_item.stack_trace, MAX_STACK_FRAMES);

    if (info->hit_item_arr) {
			if(cvector_length(info->hit_item_arr) < 1024) { // Limit buffered hits
				cvector_pushback(info->hit_item_arr, &hit_item);
			}
    }
}

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
static bool arm64_move_bp_to_next_instruction(struct perf_event *bp, uint64_t next_instruction_addr, struct perf_event_attr *original_attr, struct perf_event_attr * next_instruction_attr) {
    int result;
	if (!bp || !original_attr || !next_instruction_attr || !next_instruction_addr) {
        return false;
    }
	memcpy(next_instruction_attr, original_attr, sizeof(struct perf_event_attr));
	next_instruction_attr->bp_addr = next_instruction_addr;
	next_instruction_attr->bp_len = HW_BREAKPOINT_LEN_4;
	next_instruction_attr->bp_type = HW_BREAKPOINT_X;
	next_instruction_attr->disabled = 0;
	result = x_modify_user_hw_breakpoint(bp, next_instruction_attr);
	if(result) {
		next_instruction_attr->bp_addr = 0;
		return false;
	}
	return true;
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp, struct perf_event_attr *original_attr, struct perf_event_attr * next_instruction_attr) {
    int result;
	if (!bp || !original_attr || !next_instruction_attr) {
        return false;
    }
	result = x_modify_user_hw_breakpoint(bp, original_attr);
	if(result) {
		return false;
	}
	next_instruction_attr->bp_addr = 0;
	return true;
}
#endif

static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	citerator iter;
	uint64_t hook_pc;

	PRINT_DEBUG("[HWBP_HANDLER] HIT! pc=0x%llx, bp=%p\n", regs->pc, bp);

	hook_pc = atomic64_read(&g_hook_pc);
	if(hook_pc) {
		regs->pc = hook_pc;
		return;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp != bp) {
			continue;
		}
        
        hwbp_handle_info->hit_total_count++;
        record_hit_details(hwbp_handle_info, regs);

        // SIMPLIFIED LOGIC FOR DEBUGGING: Just disable the breakpoint.
        // We expect to get only 1 hit this way. If we get 0, the handler isn't being called.
        // If we get 1, the handler is called, but the original re-arming logic was failing.
		toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
		break; // Found and handled, no need to continue loop
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
}

// --- Public API Implementation ---

int khack_hw_breakpoint_init(void) {
    int ret = 0;
    atomic64_set(&g_hook_pc, 0);
    mutex_init(&g_hwbp_handle_info_mutex);
    g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
    if (!g_hwbp_handle_info_arr) {
        return -ENOMEM;
    }

    ret = hwbp_resolve_api_symbols();
    if (ret != 0) {
        return ret;
    }

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    ret = anti_ptrace_init(&g_hwbp_handle_info_arr, &g_hwbp_handle_info_mutex);
    if (ret != 0) {
        PRINT_DEBUG("[-] Failed to init anti ptrace detection\n");
        // Not a fatal error, we can continue without it
    }
#endif

    PRINT_DEBUG("[+] hw_breakpoint module initialized.\n");
    return 0;
}

void khack_hw_breakpoint_exit(void) {
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    anti_ptrace_exit();
#endif
    clean_all_hwbp();
    mutex_destroy(&g_hwbp_handle_info_mutex);
    PRINT_DEBUG("[+] hw_breakpoint module exited.\n");
}

long hwbp_get_num_brps(void) {
    return getCpuNumBrps();
}

long hwbp_get_num_wrps(void) {
    return getCpuNumWrps();
}

long hwbp_install(pid_t pid, uint64_t addr, int len, int type, uint64_t* handle_out) {
    struct task_struct *task;
    struct HWBP_HANDLE_INFO hwbp_handle_info = { 0 };
    int ret;

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) {
        return -ESRCH;
    }

    hwbp_handle_info.task_id = pid;
    hwbp_handle_info.is_32bit_task = is_compat_thread(task_thread_info(task));
    
    hwbp_handle_info.original_attr.size = sizeof(struct perf_event_attr);
    hwbp_handle_info.original_attr.bp_addr = addr;
    hwbp_handle_info.original_attr.bp_len = len;
    hwbp_handle_info.original_attr.bp_type = type;
    hwbp_handle_info.original_attr.disabled = 0;

    PRINT_DEBUG("[HWBP_INSTALL] pid=%d, addr=0x%llx, len=%d, type=%d\n", pid, addr, len, type);

    hwbp_handle_info.sample_hbp = x_register_user_hw_breakpoint(&hwbp_handle_info.original_attr, hwbp_handler, NULL, task);
    put_task_struct(task);

    if (IS_ERR(hwbp_handle_info.sample_hbp)) {
        ret = PTR_ERR(hwbp_handle_info.sample_hbp);
        PRINT_DEBUG("[-] register_user_hw_breakpoint failed: %d\n", ret);
        return ret;
    }

    hwbp_handle_info.hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
    if (!hwbp_handle_info.hit_item_arr) {
        x_unregister_hw_breakpoint(hwbp_handle_info.sample_hbp);
        return -ENOMEM;
    }

    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector_pushback(g_hwbp_handle_info_arr, &hwbp_handle_info);
    mutex_unlock(&g_hwbp_handle_info_mutex);

    *handle_out = (uint64_t)hwbp_handle_info.sample_hbp;
    return 0;
}

long hwbp_uninstall(uint64_t handle) {
    struct perf_event * sample_hbp = (struct perf_event *)handle;
    citerator iter;
	bool found = false;

    if (!sample_hbp) return -EINVAL;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			if(hwbp_handle_info->hit_item_arr) {
				cvector_destroy(hwbp_handle_info->hit_item_arr);
				hwbp_handle_info->hit_item_arr = NULL;
			}
			cvector_rm(g_hwbp_handle_info_arr, iter);
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);

	if(found) {
		x_unregister_hw_breakpoint(sample_hbp);
	}
    return found ? 0 : -ENOENT;
}

static struct HWBP_HANDLE_INFO* find_hwbp_info(uint64_t handle) {
    citerator iter;
    struct perf_event * sample_hbp = (struct perf_event *)handle;
    if (!sample_hbp) return NULL;

    for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
        struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
        if (info->sample_hbp == sample_hbp) {
            return info;
        }
    }
    return NULL;
}

long hwbp_suspend(uint64_t handle) {
    struct HWBP_HANDLE_INFO *info;
    int ret = -ENOENT;
    mutex_lock(&g_hwbp_handle_info_mutex);
    info = find_hwbp_info(handle);
    if (info) {
        toggle_bp_registers_directly(&info->original_attr, info->is_32bit_task, 0);
        ret = 0;
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return ret;
}

long hwbp_resume(uint64_t handle) {
    struct HWBP_HANDLE_INFO *info;
    int ret = -ENOENT;
    mutex_lock(&g_hwbp_handle_info_mutex);
    info = find_hwbp_info(handle);
    if (info) {
        toggle_bp_registers_directly(&info->original_attr, info->is_32bit_task, 1);
        ret = 0;
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return ret;
}

long hwbp_get_hit_count(uint64_t handle, uint64_t* total_count, uint64_t* arr_count) {
    struct HWBP_HANDLE_INFO *info;
    int ret = -ENOENT;
    mutex_lock(&g_hwbp_handle_info_mutex);
    info = find_hwbp_info(handle);
    if (info) {
        *total_count = info->hit_total_count;
        *arr_count = info->hit_item_arr ? cvector_length(info->hit_item_arr) : 0;
        ret = 0;
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return ret;
}

long hwbp_get_hit_detail(uint64_t handle, void __user *buf, size_t size) {
    struct HWBP_HANDLE_INFO *info;
    long count = 0;
    size_t bytes_to_copy;

    mutex_lock(&g_hwbp_handle_info_mutex);
    info = find_hwbp_info(handle);
    if (!info || !info->hit_item_arr) {
        mutex_unlock(&g_hwbp_handle_info_mutex);
        return -ENOENT;
    }

    count = cvector_length(info->hit_item_arr);
    bytes_to_copy = min(size, count * sizeof(struct HWBP_HIT_ITEM));

    if (bytes_to_copy > 0) {
        if (copy_to_user(buf, cvector_begin(info->hit_item_arr), bytes_to_copy)) {
            mutex_unlock(&g_hwbp_handle_info_mutex);
            return -EFAULT;
        }
    }
    
    // Clear the buffer after reading
    cvector_destroy(info->hit_item_arr);
    info->hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));

    mutex_unlock(&g_hwbp_handle_info_mutex);
    return bytes_to_copy / sizeof(struct HWBP_HIT_ITEM);
}

long hwbp_set_redirect_pc(uint64_t pc) {
    atomic64_set(&g_hook_pc, pc);
    return 0;
}

static void clean_all_hwbp(void) {
	citerator iter;
	cvector wait_unregister_bp_arr = cvector_create(sizeof(struct perf_event *));
	if(!wait_unregister_bp_arr || !g_hwbp_handle_info_arr) {
		return;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp) {
			cvector_pushback(wait_unregister_bp_arr, &hwbp_handle_info->sample_hbp);
			hwbp_handle_info->sample_hbp = NULL;
		}
		if(hwbp_handle_info->hit_item_arr) {
			cvector_destroy(hwbp_handle_info->hit_item_arr);
			hwbp_handle_info->hit_item_arr = NULL;
		}
	}
	cvector_destroy(g_hwbp_handle_info_arr);
	g_hwbp_handle_info_arr = NULL;
	mutex_unlock(&g_hwbp_handle_info_mutex);
	
	for (iter = cvector_begin(wait_unregister_bp_arr); iter != cvector_end(wait_unregister_bp_arr); iter = cvector_next(wait_unregister_bp_arr, iter)) {
	  struct perf_event * bp = *(struct perf_event **)iter;
	  x_unregister_hw_breakpoint(bp);
	}
	cvector_destroy(wait_unregister_bp_arr);
}
