#include <linux/kprobes.h> // for pt_regs
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/uio.h> // for iovec
#include <linux/uaccess.h>

#include "anti_ptrace_detection.h"
#include "hw_breakpoint.h" // For HWBP_HANDLE_INFO
#include "inline_hook/p_hook.h"
#include "inline_hook/p_lkrg_main.h"
#include "version_control.h"

#define PTRACE_GETREGSET   0x4204
#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403

// Globals to hold pointers passed from hw_breakpoint.c
static cvector *g_p_hwbp_handle_info_arr = NULL;
static struct mutex *g_p_hwbp_handle_info_mutex = NULL;
static void *g_arch_ptrace_addr = NULL;


static bool is_my_hwbp_handle_addr(size_t addr) {
	citerator iter;
	bool found = false;
	if(addr == 0) {
		return found;
	}
	mutex_lock(g_p_hwbp_handle_info_mutex);
	for (iter = cvector_begin(*g_p_hwbp_handle_info_arr); iter != cvector_end(*g_p_hwbp_handle_info_arr); iter = cvector_next(*g_p_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->original_attr.bp_addr == addr) {
			found = true;
			break;
		}
	}
	mutex_unlock(g_p_hwbp_handle_info_mutex);
	return found;
}

static void ptrace_before_callback(hook_fargs4_t *fargs, void *udata)
{
    long request = (long)fargs->arg1;
    unsigned long addr = (unsigned long)fargs->arg2;
    unsigned long data = (unsigned long)fargs->arg3;

    if (request == PTRACE_GETREGSET && (addr == NT_ARM_HW_WATCH || addr == NT_ARM_HW_BREAK)) {
        if(data) {
            // Store the user iovec pointer for the 'after' callback
            fargs->local.data[0] = data;
        }
    }
}

static void ptrace_after_callback(hook_fargs4_t *fargs, void *udata)
{
    struct iovec iov;
    struct user_hwdebug_state old_hw_state;
    struct user_hwdebug_state new_hw_state;
    size_t copy_size;
    int i = 0, y = 0;
    unsigned long iov_user_ptr = fargs->local.data[0];

    // Check if we stored the iovec pointer in the 'before' callback
    if (!iov_user_ptr) {
        return;
    }

    // We are in the return path of a PTRACE_GETREGSET for HW breakpoints
    if (copy_from_user(&iov, (struct iovec __user *)iov_user_ptr, sizeof(struct iovec)) != 0) {
        PRINT_DEBUG("[-] anti_ptrace: Failed to copy iovec from user space\n");
        return;
    }

    if (!iov.iov_base || !iov.iov_len) {
        return;
    }

    if (!access_ok((void __user *)iov.iov_base, iov.iov_len)) {
        PRINT_DEBUG("[-] anti_ptrace: User buffer is not accessible\n");
        return;
    }

    copy_size = min(iov.iov_len, sizeof(struct user_hwdebug_state));
    if (copy_from_user(&old_hw_state, (void __user *)iov.iov_base, copy_size) != 0) {
        PRINT_DEBUG("[-] anti_ptrace: Failed to copy old_hw_state from user buffer\n");
        return;
    }

    // Clear our breakpoints from the state
    memcpy(&new_hw_state, &old_hw_state, sizeof(new_hw_state));
    memset(new_hw_state.dbg_regs, 0x00, sizeof(new_hw_state.dbg_regs));

    for (i = 0; i < ARM_MAX_BRP_REGS; i++) { // ARM_MAX_BRP_REGS is usually 16
        if(!is_my_hwbp_handle_addr(old_hw_state.dbg_regs[i].addr)) {
            if (y < ARM_MAX_BRP_REGS) {
                memcpy(&new_hw_state.dbg_regs[y++], &old_hw_state.dbg_regs[i], sizeof(old_hw_state.dbg_regs[i]));
            }
        }
    }

    // Copy the modified (cleaned) state back to the user-space buffer
    if (copy_to_user((void __user *)iov.iov_base, &new_hw_state, copy_size) != 0) {
        PRINT_DEBUG("[-] anti_ptrace: Failed to copy modified new_hw_state back to user buffer\n");
    }
}


int anti_ptrace_init(cvector *p_hwbp_handle_info_arr, struct mutex *p_mutex)
{
    hook_err_t err;

    g_p_hwbp_handle_info_arr = p_hwbp_handle_info_arr;
    g_p_hwbp_handle_info_mutex = p_mutex;

    if (!g_p_hwbp_handle_info_arr || !g_p_hwbp_handle_info_mutex) {
        PRINT_DEBUG("[-] anti_ptrace: Invalid arguments.\n");
        return -EINVAL;
    }

    g_arch_ptrace_addr = (void *)P_SYM(p_kallsyms_lookup_name)("arch_ptrace");
    if (!g_arch_ptrace_addr) {
        PRINT_DEBUG("[-] anti_ptrace: Failed to find arch_ptrace address.\n");
        return -ENOENT;
    }

    // arch_ptrace has 4 arguments
    err = hook_wrap4(g_arch_ptrace_addr, ptrace_before_callback, ptrace_after_callback, NULL);
    if (err != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] anti_ptrace: Failed to wrap arch_ptrace, error %d\n", err);
        g_arch_ptrace_addr = NULL;
        return -EFAULT;
    }

    PRINT_DEBUG("[+] anti_ptrace: Successfully hooked arch_ptrace.\n");
    return 0;
}

void anti_ptrace_exit(void)
{
    if (g_arch_ptrace_addr) {
        hook_unwrap(g_arch_ptrace_addr, ptrace_before_callback, ptrace_after_callback);
        g_arch_ptrace_addr = NULL;
        PRINT_DEBUG("[+] anti_ptrace: Unhooked arch_ptrace.\n");
    }
}
