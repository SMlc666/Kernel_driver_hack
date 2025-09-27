#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>

#include "anti_ptrace_detection.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/p_hook.h"

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE

#define PTRACE_GETREGSET   0x4204
#define NT_ARM_HW_BREAK	0x402
#define NT_ARM_HW_WATCH	0x403

static void *g_arch_ptrace_addr = NULL;

// Forward declarations
static void before_arch_ptrace(hook_fargs4_t *fargs, void *udata);
static void after_arch_ptrace(hook_fargs4_t *fargs, void *udata);

static void before_arch_ptrace(hook_fargs4_t *fargs, void *udata) {
    long request = (long)fargs->arg1;
    unsigned long addr = (unsigned long)fargs->arg2;

    // Clear local data to ensure it's clean for this run
    fargs->local.data[0] = 0;
    fargs->local.data[1] = 0;

    if (request == PTRACE_GETREGSET && (addr == NT_ARM_HW_WATCH || addr == NT_ARM_HW_BREAK)) {
        unsigned long iov_user_ptr = fargs->arg3;
        struct iovec iov;

        if(!iov_user_ptr) {
            return;
        }
        if (copy_from_user(&iov, (struct iovec __user *)iov_user_ptr, sizeof(struct iovec)) != 0) {
            PRINT_DEBUG("[-] anti-ptrace: Failed to copy iovec from user space\n");
            return;
        }
        
        // Store iov_base and iov_len in the local data to pass to the 'after' hook
        fargs->local.data[0] = (uintptr_t)iov.iov_base;
        fargs->local.data[1] = iov.iov_len;
    }
}

static void after_arch_ptrace(hook_fargs4_t *fargs, void *udata) {
    struct user_hwdebug_state new_hw_state;
    size_t copy_size;
    void __user *iov_base = (void __user *)fargs->local.data[0];
    size_t iov_len = fargs->local.data[1];

    if (!iov_base || !iov_len) {
        return;
    }

    if (!access_ok(VERIFY_WRITE, iov_base, iov_len)) {
        PRINT_DEBUG("[-] anti-ptrace: User buffer is not accessible\n");
        return;
    }

    copy_size = min(iov_len, sizeof(struct user_hwdebug_state));
    
    // Zero out our local copy of the state
    memset(&new_hw_state, 0, sizeof(new_hw_state));

    // Copy the zeroed-out state to the user.
    if (copy_to_user(iov_base, &new_hw_state, copy_size) != 0) {
        PRINT_DEBUG("[-] anti-ptrace: Failed to copy modified new_hw_state back to user buffer\n");
    } else {
        PRINT_DEBUG("[+] anti-ptrace: Successfully hid all hw breakpoints from ptrace.\n");
    }
}

int start_anti_ptrace_detection(void) {
    if (g_arch_ptrace_addr) {
        PRINT_DEBUG("[+] anti-ptrace: Already running.\n");
        return 0;
    }

    if (P_SYM(p_kallsyms_lookup_name) == NULL) {
        PRINT_DEBUG("[-] anti-ptrace: kallsyms_lookup_name not available.\n");
        return -1;
    }

    g_arch_ptrace_addr = (void *)P_SYM(p_kallsyms_lookup_name)("arch_ptrace");
    if (!g_arch_ptrace_addr) {
        PRINT_DEBUG("[-] anti-ptrace: Failed to find address of arch_ptrace.\n");
        return -1;
    }

    if (hook_wrap(g_arch_ptrace_addr, 4, before_arch_ptrace, after_arch_ptrace, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] anti-ptrace: Failed to wrap arch_ptrace().\n");
        g_arch_ptrace_addr = NULL;
        return -1;
    }

    PRINT_DEBUG("[+] anti-ptrace: arch_ptrace() hooked successfully.\n");
    return 0;
}

void stop_anti_ptrace_detection(void) {
    if (g_arch_ptrace_addr) {
        hook_unwrap(g_arch_ptrace_addr, before_arch_ptrace, after_arch_ptrace);
        g_arch_ptrace_addr = NULL;
        PRINT_DEBUG("[+] anti-ptrace: arch_ptrace() unhooked.\n");
    }
}

#endif // CONFIG_ANTI_PTRACE_DETECTION_MODE