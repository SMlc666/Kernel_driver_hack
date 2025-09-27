#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>

/*
 * This function is declared in <asm/cpufeature.h> but not exported for
 * modules, causing a link error. We provide our own implementation here
 * to satisfy the linker.
 */
u64 read_sanitised_ftr_reg(u32 id)
{
	u64 val;

	switch (id) {
	case SYS_ID_AA64DFR0_EL1:
		val = read_sysreg(id_aa64dfr0_el1);
		break;
	default:
		pr_warn("read_sanitised_ftr_reg: unhandled reg ID %d\n", id);
		return 0;
	}

	return val;
}
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <asm/compat.h>

#include "hw_breakpoint.h"
#include "arm64_register_helper.h"
#include "api_proxy.h"
#include "anti_ptrace_detection.h"
#include "process.h"
#include <linux/kallsyms.h>

// Function pointer for the unexported read_sanitised_ftr_reg
typedef u64 (*read_sanitised_ftr_reg_t)(u32 id);
read_sanitised_ftr_reg_t read_sanitised_ftr_reg_ptr;

// --- Globals ---
static atomic64_t g_redirect_pc;
static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr = NULL;

// --- Forward Declarations ---
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);

// --- Helper Functions ---

struct mutex *hwbp_get_mutex(void) {
    return &g_hwbp_handle_info_mutex;
}

cvector *hwbp_get_vector(void) {
    return &g_hwbp_handle_info_arr;
}

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
    if (info->hit_item_arr) {
		if(cvector_length(info->hit_item_arr) < MIN_LEN) { // Cap the number of stored hits
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

static void hwbp_hit_user_info_callback(struct perf_event *bp,
	struct perf_sample_data *data,
	struct pt_regs *regs, struct HWBP_HANDLE_INFO * hwbp_handle_info) {
	hwbp_handle_info->hit_total_count++;
	record_hit_details(hwbp_handle_info, regs);
}


// --- Main Breakpoint Handler ---

static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	citerator iter;
	uint64_t redirect_pc;
	PRINT_DEBUG("[HWBP] HIT! bp:%px, pc:%px, id:%d\n", bp, (void*)regs->pc, bp->id);

	redirect_pc = atomic64_read(&g_redirect_pc);
	if(redirect_pc) {
		regs->pc = redirect_pc;
		return;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp != bp) {
			continue;
		}

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
		if(hwbp_handle_info->next_instruction_attr.bp_addr != regs->pc) {
			// First hit at the original address
			bool should_toggle = true;
			hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
			if(!hwbp_handle_info->is_32bit_task) {
				if(arm64_move_bp_to_next_instruction(bp, regs->pc + 4, &hwbp_handle_info->original_attr, &hwbp_handle_info->next_instruction_attr)) {
					should_toggle = false;
				}
			}
			if(should_toggle) {
				toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
			}
		} else {
			// Second hit at the next instruction address
			if(!arm64_recovery_bp_to_original(bp, &hwbp_handle_info->original_attr, &hwbp_handle_info->next_instruction_attr)) {
				toggle_bp_registers_directly(&hwbp_handle_info->next_instruction_attr, hwbp_handle_info->is_32bit_task, 0);
			}
		}
#else
		hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
		toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
#endif
		break; // Found our handle, no need to continue loop
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
}

// --- Public API Implementation ---

int khack_hw_breakpoint_init(void) {
    read_sanitised_ftr_reg_ptr = (read_sanitised_ftr_reg_t)kallsyms_lookup_name("read_sanitised_ftr_reg");
    if (!read_sanitised_ftr_reg_ptr) {
        PRINT_DEBUG("[-] Failed to resolve read_sanitised_ftr_reg via kallsyms\n");
        return -ENOENT;
    }

    if (hwbp_resolve_api_symbols() != 0) {
        PRINT_DEBUG("[-] Failed to resolve HWBP API symbols.\n");
        return -1;
    }

	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
	if (!g_hwbp_handle_info_arr) {
        return -ENOMEM;
    }
	mutex_init(&g_hwbp_handle_info_mutex);
    atomic64_set(&g_redirect_pc, 0);

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    if (start_anti_ptrace_detection() != 0) {
        PRINT_DEBUG("[!] Failed to start anti-ptrace detection.\n");
        // Non-fatal, continue anyway
    }
#endif

    PRINT_DEBUG("[+] HW Breakpoint subsystem initialized.\n");
	return 0;
}

void khack_hw_breakpoint_exit(void) {
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    stop_anti_ptrace_detection();
#endif

	if (g_hwbp_handle_info_arr) {
        citerator iter;
        cvector wait_unregister_bp_arr = cvector_create(sizeof(struct perf_event *));
        if (!wait_unregister_bp_arr) return;

        mutex_lock(&g_hwbp_handle_info_mutex);
        for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
            struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
            if(info->sample_hbp) {
                cvector_pushback(wait_unregister_bp_arr, &info->sample_hbp);
            }
            if(info->hit_item_arr) {
                cvector_destroy(info->hit_item_arr);
            }
        }
        cvector_destroy(g_hwbp_handle_info_arr);
        g_hwbp_handle_info_arr = NULL;
        mutex_unlock(&g_hwbp_handle_info_mutex);

        for (iter = cvector_begin(wait_unregister_bp_arr); iter != cvector_end(wait_unregister_bp_arr); iter = cvector_next(wait_unregister_bp_arr, iter)) {
            struct perf_event *bp = *(struct perf_event **)iter;
            x_unregister_hw_breakpoint(bp);
        }
        cvector_destroy(wait_unregister_bp_arr);
    }
	mutex_destroy(&g_hwbp_handle_info_mutex);
    PRINT_DEBUG("[+] HW Breakpoint subsystem exited.\n");
}

int hwbp_get_num_brps(void) {
	return get_num_brps();
}

int hwbp_get_num_wrps(void) {
	return get_num_wrps();
}

int hwbp_install(pid_t pid, uintptr_t addr, int len, int type, uint64_t *handle) {
    struct task_struct *task;
    struct HWBP_HANDLE_INFO hwbp_handle_info = {0};
    int ret = 0;

    PRINT_DEBUG("hwbp_install: pid=%d, addr=0x%lx, len=%d, type=%d\n", pid, (unsigned long)addr, len, type);
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) {
        PRINT_DEBUG("[-] hwbp_install: Could not find task for PID %d\n", pid);
        return -ESRCH;
    }

    hwbp_handle_info.task_id = pid;
    hwbp_handle_info.is_32bit_task = is_compat_thread(task_thread_info(task));

    hwbp_handle_info.original_attr.type = PERF_TYPE_BREAKPOINT;
    hwbp_handle_info.original_attr.pinned = 1;
    hwbp_handle_info.original_attr.bp_addr = addr;
    hwbp_handle_info.original_attr.bp_len = len;
    hwbp_handle_info.original_attr.bp_type = type;
    hwbp_handle_info.original_attr.disabled = 0;

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

    hwbp_handle_info.handle = (uint64_t)hwbp_handle_info.sample_hbp;
    *handle = hwbp_handle_info.handle;

    mutex_lock(&g_hwbp_handle_info_mutex);
    cvector_pushback(g_hwbp_handle_info_arr, &hwbp_handle_info);
    mutex_unlock(&g_hwbp_handle_info_mutex);

    PRINT_DEBUG("[+] HWBP installed with handle %llx for PID %d at addr %px\n", *handle, pid, (void*)addr);
    return 0;
}

int hwbp_uninstall(uint64_t handle) {
    citerator iter;
    bool found = false;
    struct perf_event *sample_hbp = (struct perf_event *)handle;

    if (!sample_hbp) return -EINVAL;

    mutex_lock(&g_hwbp_handle_info_mutex);
    for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
        struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
        if (info->handle == handle) {
            if (info->hit_item_arr) {
                cvector_destroy(info->hit_item_arr);
            }
            cvector_rm(g_hwbp_handle_info_arr, iter);
            found = true;
            break;
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);

    if (found) {
        x_unregister_hw_breakpoint(sample_hbp);
        PRINT_DEBUG("[+] HWBP with handle %llx uninstalled.\n", handle);
        return 0;
    }
    return -ENOENT;
}

static int modify_bp_disabled(uint64_t handle, int disabled) {
    citerator iter;
    bool found = false;
    struct perf_event_attr new_attr;
    struct perf_event *sample_hbp = (struct perf_event *)handle;
    int ret = -ENOENT;

    if (!sample_hbp) return -EINVAL;

    mutex_lock(&g_hwbp_handle_info_mutex);
    for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
        struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
        if (info->handle == handle) {
            info->original_attr.disabled = disabled;
            memcpy(&new_attr, &info->original_attr, sizeof(struct perf_event_attr));
            found = true;
            break;
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);

    if (found) {
        ret = x_modify_user_hw_breakpoint(sample_hbp, &new_attr);
    }
    return ret;
}

int hwbp_suspend(uint64_t handle) {
    return modify_bp_disabled(handle, 1);
}

int hwbp_resume(uint64_t handle) {
    return modify_bp_disabled(handle, 0);
}

int hwbp_get_hit_count(uint64_t handle, uint64_t *total_count, uint64_t *arr_count) {
    citerator iter;
    int ret = -ENOENT;

    mutex_lock(&g_hwbp_handle_info_mutex);
    for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
        struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
        if (info->handle == handle) {
            *total_count = info->hit_total_count;
            *arr_count = cvector_length(info->hit_item_arr);
            ret = 0;
            break;
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return ret;
}

int hwbp_get_hit_detail(uint64_t handle, void __user *buffer, size_t size) {
    citerator iter;
    int ret = -ENOENT;
    size_t bytes_to_copy = 0;
    size_t bytes_copied = 0;

    mutex_lock(&g_hwbp_handle_info_mutex);
    for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
        struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
        if (info->handle == handle && info->hit_item_arr) {
            citerator child;
            bytes_to_copy = cvector_length(info->hit_item_arr) * sizeof(struct HWBP_HIT_ITEM);
            if (size < bytes_to_copy) {
                bytes_to_copy = size;
            }

            if (copy_to_user(buffer, cvector_begin(info->hit_item_arr), bytes_to_copy)) {
                ret = -EFAULT;
            } else {
                bytes_copied = bytes_to_copy;
                // Clear the buffer after reading
                cvector_destroy(info->hit_item_arr);
                info->hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
                ret = bytes_copied;
            }
            break;
        }
    }
    mutex_unlock(&g_hwbp_handle_info_mutex);
    return ret;
}

int hwbp_set_redirect_pc(uint64_t pc) {
    atomic64_set(&g_redirect_pc, pc);
    return 0;
}

