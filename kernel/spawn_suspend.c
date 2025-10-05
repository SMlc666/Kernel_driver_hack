#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/binfmts.h> // For kbasename
#include <linux/string.h>
#include <linux/spinlock.h>

#include "spawn_suspend.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/p_hook.h"
#include "version_control.h"

#define TARGET_NAME_MAX 256

// --- Global state for the target ---
static char g_spawn_suspend_target[TARGET_NAME_MAX];
static bool g_suspend_enabled = false;
static DEFINE_SPINLOCK(g_suspend_lock);

// --- Original function pointer ---
static void *g_execve_addr = NULL;

// --- Hook function ---
static void before_execve(hook_fargs1_t *fargs, void *udata)
{
    const char __user *filename_user = (const char __user *)fargs->arg0;
    char *filename;
    const char __user *const __user *argv_user;
    int i;

    spin_lock(&g_suspend_lock);
    if (!g_suspend_enabled || g_spawn_suspend_target[0] == '\0') {
        spin_unlock(&g_suspend_lock);
        return;
    }
    spin_unlock(&g_suspend_lock);

    filename = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!filename) {
        return;
    }

    if (strncpy_from_user(filename, filename_user, PATH_MAX - 1) < 0) {
        kfree(filename);
        return;
    }
    filename[PATH_MAX - 1] = '\0';

    PRINT_DEBUG("[spawn_suspend] Checking execve for process: %s (PID: %d)\n", filename, current->pid);

    // Log argv
    argv_user = (const char __user *const __user *)fargs->arg1;
    if (argv_user) {
        char arg_buf[256];
        i = 0;
        const char __user *arg_ptr;
        
        while (get_user(arg_ptr, argv_user + i) == 0 && arg_ptr) {
            long len = strncpy_from_user(arg_buf, arg_ptr, sizeof(arg_buf) - 1);
            if (len < 0) {
                PRINT_DEBUG("[spawn_suspend] argv[%d]: <fault>\n", i);
            } else {
                arg_buf[sizeof(arg_buf) - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] argv[%d]: %s\n", i, arg_buf);
            }
            i++;
            if (i > 32) { // Safety break
                PRINT_DEBUG("[spawn_suspend] argv: too many arguments, stopping log.\n");
                break;
            }
        }
    }

    spin_lock(&g_suspend_lock);
    if (g_suspend_enabled && strstr(filename, g_spawn_suspend_target) != NULL) {
        PRINT_DEBUG("[spawn_suspend] Target '%s' matched in path '%s' for PID %d. Sending SIGSTOP.\n", g_spawn_suspend_target, filename, current->pid);
        
        force_sig(SIGSTOP, current);
    }
    spin_unlock(&g_suspend_lock);
    kfree(filename);
}

// --- Public control function ---
void set_spawn_suspend_target(const char *name, int enable)
{
    spin_lock(&g_suspend_lock);
    if (enable && name) {
        strncpy(g_spawn_suspend_target, name, TARGET_NAME_MAX - 1);
        g_spawn_suspend_target[TARGET_NAME_MAX - 1] = '\0';
        g_suspend_enabled = true;
        PRINT_DEBUG("[spawn_suspend] Target set to '%s'.\n", g_spawn_suspend_target);
    } else {
        g_spawn_suspend_target[0] = '\0';
        g_suspend_enabled = false;
        PRINT_DEBUG("[spawn_suspend] Target cleared.\n");
    }
    spin_unlock(&g_suspend_lock);
}

// --- Init and Exit ---
int spawn_suspend_init(void)
{
    // Find the address of the execve syscall handler. On arm64, it's often __arm64_sys_execve.
    // The exact name can vary, so checking kallsyms is necessary.
    g_execve_addr = (void *)kallsyms_lookup_name("__arm64_sys_execve");
    if (!g_execve_addr) {
        g_execve_addr = (void *)kallsyms_lookup_name("do_execve");
        if (!g_execve_addr) {
            PRINT_DEBUG("[-] spawn_suspend: Failed to find execve syscall handler.\n");
            return -1;
        }
    }

    // The execve syscall has 3 arguments, but we only need the first one.
    // hook_wrap with arg count 1 (which maps to hook_fargs4_t) is sufficient.
    if (hook_wrap(g_execve_addr, 1, before_execve, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] spawn_suspend: Failed to wrap execve().\n");
        g_execve_addr = NULL;
        return -1;
    }

    PRINT_DEBUG("[+] spawn_suspend: execve() wrapped successfully at %p.\n", g_execve_addr);
    return 0;
}

void spawn_suspend_exit(void)
{
    if (g_execve_addr) {
        hook_unwrap(g_execve_addr, before_execve, NULL);
        g_execve_addr = NULL;
        PRINT_DEBUG("[+] spawn_suspend: execve() unwrapped.\n");
    }
    set_spawn_suspend_target(NULL, 0); // Clear target on exit
}
