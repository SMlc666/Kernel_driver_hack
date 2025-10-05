#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/prctl.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>

#include "spawn_suspend.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/utils/p_memory.h"
#include "version_control.h"

#define TARGET_NAME_MAX 256

// --- Global state for the target ---
static char g_spawn_suspend_target[TARGET_NAME_MAX];
static bool g_suspend_enabled = false;
static DEFINE_SPINLOCK(g_suspend_lock);

// --- Syscall table and original pointers ---
static unsigned long **p_sys_call_table = NULL;

// Define types for the syscall function pointers
typedef asmlinkage long (*sys_execve_t)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
typedef asmlinkage long (*sys_execveat_t)(int fd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
typedef asmlinkage long (*sys_prctl_t)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

static sys_execve_t original_sys_execve;
static sys_execveat_t original_sys_execveat;
static sys_prctl_t original_sys_prctl;


// --- Hooked Syscall Functions ---

static asmlinkage long hooked_sys_execve(const char __user *filename_user, const char __user *const __user *argv, const char __user *const __user *envp)
{
    char target_name_copy[TARGET_NAME_MAX];
    bool enabled_copy;

    spin_lock(&g_suspend_lock);
    enabled_copy = g_suspend_enabled;
    if (enabled_copy) {
        strncpy(target_name_copy, g_spawn_suspend_target, TARGET_NAME_MAX);
    }
    spin_unlock(&g_suspend_lock);

    if (enabled_copy && target_name_copy[0] != '\0') {
        char *filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            if (strncpy_from_user(filename, filename_user, PATH_MAX - 1) >= 0) {
                filename[PATH_MAX - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] execve: %s\n", filename);

                if (strstr(filename, target_name_copy) != NULL) {
                    PRINT_DEBUG("[spawn_suspend] Target '%s' matched execve path '%s'. Stopping PID %d.\n", target_name_copy, filename, current->pid);
                    force_sig(SIGSTOP, current);
                }
            }
            kfree(filename);
        }
    }

    return original_sys_execve(filename_user, argv, envp);
}

static asmlinkage long hooked_sys_execveat(int fd, const char __user *filename_user, const char __user *const __user *argv, const char __user *const __user *envp, int flags)
{
    char target_name_copy[TARGET_NAME_MAX];
    bool enabled_copy;

    spin_lock(&g_suspend_lock);
    enabled_copy = g_suspend_enabled;
    if (enabled_copy) {
        strncpy(target_name_copy, g_spawn_suspend_target, TARGET_NAME_MAX);
    }
    spin_unlock(&g_suspend_lock);

    if (enabled_copy && target_name_copy[0] != '\0') {
        char *filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            if (strncpy_from_user(filename, filename_user, PATH_MAX - 1) >= 0) {
                filename[PATH_MAX - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] execveat: %s\n", filename);

                if (strstr(filename, target_name_copy) != NULL) {
                    PRINT_DEBUG("[spawn_suspend] Target '%s' matched execveat path '%s'. Stopping PID %d.\n", target_name_copy, filename, current->pid);
                    force_sig(SIGSTOP, current);
                }
            }
            kfree(filename);
        }
    }

    return original_sys_execveat(fd, filename_user, argv, envp, flags);
}

static asmlinkage long hooked_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    if (option == PR_SET_NAME) {
        char target_name_copy[TARGET_NAME_MAX];
        bool enabled_copy;

        spin_lock(&g_suspend_lock);
        enabled_copy = g_suspend_enabled;
        if (enabled_copy) {
            strncpy(target_name_copy, g_spawn_suspend_target, TARGET_NAME_MAX);
        }
        spin_unlock(&g_suspend_lock);

        if (enabled_copy && target_name_copy[0] != '\0') {
            char name_buf[TASK_COMM_LEN];
            const char __user *name_user = (const char __user *)arg2;

            if (strncpy_from_user(name_buf, name_user, sizeof(name_buf) - 1) >= 0) {
                name_buf[sizeof(name_buf) - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] prctl(PR_SET_NAME): %s\n", name_buf);

                if (strcmp(name_buf, target_name_copy) == 0) {
                    PRINT_DEBUG("[spawn_suspend] Target '%s' matched process name. Stopping PID %d.\n", target_name_copy, current->pid);
                    force_sig(SIGSTOP, current);
                }
            }
        }
    }

    return original_sys_prctl(option, arg2, arg3, arg4, arg5);
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
    p_sys_call_table = (unsigned long **)get_sys_call_table();
    if (!p_sys_call_table) {
        PRINT_DEBUG("[-] spawn_suspend: Failed to get sys_call_table address.\n");
        return -EFAULT;
    }
    PRINT_DEBUG("[+] spawn_suspend: Found sys_call_table at %p\n", p_sys_call_table);

    // Backup original syscalls
    original_sys_execve = (void *)p_sys_call_table[__NR_execve];
    original_sys_execveat = (void *)p_sys_call_table[__NR_execveat];
    original_sys_prctl = (void *)p_sys_call_table[__NR_prctl];

    // Write our hooks
    void *hook_execve_ptr = &hooked_sys_execve;
    void *hook_execveat_ptr = &hooked_sys_execveat;
    void *hook_prctl_ptr = &hooked_sys_prctl;

    if (remap_write_range(&p_sys_call_table[__NR_execve], &hook_execve_ptr, sizeof(void *), true)) {
        PRINT_DEBUG("[-] spawn_suspend: Failed to hook sys_execve.\n");
    } else {
        PRINT_DEBUG("[+] spawn_suspend: Successfully hooked sys_execve.\n");
    }

    if (remap_write_range(&p_sys_call_table[__NR_execveat], &hook_execveat_ptr, sizeof(void *), true)) {
        PRINT_DEBUG("[-] spawn_suspend: Failed to hook sys_execveat.\n");
    } else {
        PRINT_DEBUG("[+] spawn_suspend: Successfully hooked sys_execveat.\n");
    }

    if (remap_write_range(&p_sys_call_table[__NR_prctl], &hook_prctl_ptr, sizeof(void *), true)) {
        PRINT_DEBUG("[-] spawn_suspend: Failed to hook sys_prctl.\n");
    } else {
        PRINT_DEBUG("[+] spawn_suspend: Successfully hooked sys_prctl.\n");
    }

    return 0;
}

void spawn_suspend_exit(void)
{
    if (p_sys_call_table) {
        if (original_sys_execve && remap_write_range(&p_sys_call_table[__NR_execve], &original_sys_execve, sizeof(void *), true)) {
            PRINT_DEBUG("[-] spawn_suspend: Failed to restore sys_execve.\n");
        }
        if (original_sys_execveat && remap_write_range(&p_sys_call_table[__NR_execveat], &original_sys_execveat, sizeof(void *), true)) {
            PRINT_DEBUG("[-] spawn_suspend: Failed to restore sys_execveat.\n");
        }
        if (original_sys_prctl && remap_write_range(&p_sys_call_table[__NR_prctl], &original_sys_prctl, sizeof(void *), true)) {
            PRINT_DEBUG("[-] spawn_suspend: Failed to restore sys_prctl.\n");
        }
    }
    set_spawn_suspend_target(NULL, 0);
    PRINT_DEBUG("[+] spawn_suspend: Unloaded.\n");
}