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
static asmlinkage long (*original_sys_execve)(const struct pt_regs *);
static asmlinkage long (*original_sys_execveat)(const struct pt_regs *);
static asmlinkage long (*original_sys_prctl)(const struct pt_regs *);

// --- Hooked Syscall Functions ---

static asmlinkage long hooked_sys_execve(const struct pt_regs *regs)
{
    char *filename;

    spin_lock(&g_suspend_lock);
    if (g_suspend_enabled && g_spawn_suspend_target[0] != '\0') {
        const char __user *filename_user = (const char __user *)regs->regs[0];
        spin_unlock(&g_suspend_lock);

        filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            if (strncpy_from_user(filename, filename_user, PATH_MAX - 1) >= 0) {
                filename[PATH_MAX - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] execve: %s\n", filename);

                spin_lock(&g_suspend_lock);
                if (g_suspend_enabled && strstr(filename, g_spawn_suspend_target) != NULL) {
                    PRINT_DEBUG("[spawn_suspend] Target '%s' matched execve path '%s'. Stopping PID %d.\n", g_spawn_suspend_target, filename, current->pid);
                    force_sig(SIGSTOP, current);
                }
                spin_unlock(&g_suspend_lock);
            }
            kfree(filename);
        }
    } else {
        spin_unlock(&g_suspend_lock);
    }

    return original_sys_execve(regs);
}

static asmlinkage long hooked_sys_execveat(const struct pt_regs *regs)
{
    char *filename;

    spin_lock(&g_suspend_lock);
    if (g_suspend_enabled && g_spawn_suspend_target[0] != '\0') {
        const char __user *filename_user = (const char __user *)regs->regs[1];
        spin_unlock(&g_suspend_lock);

        filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            if (strncpy_from_user(filename, filename_user, PATH_MAX - 1) >= 0) {
                filename[PATH_MAX - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] execveat: %s\n", filename);

                spin_lock(&g_suspend_lock);
                if (g_suspend_enabled && strstr(filename, g_spawn_suspend_target) != NULL) {
                    PRINT_DEBUG("[spawn_suspend] Target '%s' matched execveat path '%s'. Stopping PID %d.\n", g_spawn_suspend_target, filename, current->pid);
                    force_sig(SIGSTOP, current);
                }
                spin_unlock(&g_suspend_lock);
            }
            kfree(filename);
        }
    } else {
        spin_unlock(&g_suspend_lock);
    }

    return original_sys_execveat(regs);
}

static asmlinkage long hooked_sys_prctl(const struct pt_regs *regs)
{
    int option = (int)regs->regs[0];

    if (option == PR_SET_NAME) {
        char name_buf[TASK_COMM_LEN];

        spin_lock(&g_suspend_lock);
        if (g_suspend_enabled && g_spawn_suspend_target[0] != '\0') {
            const char __user *name_user = (const char __user *)regs->regs[1];
            spin_unlock(&g_suspend_lock);

            if (strncpy_from_user(name_buf, name_user, sizeof(name_buf) - 1) >= 0) {
                name_buf[sizeof(name_buf) - 1] = '\0';
                PRINT_DEBUG("[spawn_suspend] prctl(PR_SET_NAME): %s\n", name_buf);

                spin_lock(&g_suspend_lock);
                if (g_suspend_enabled && strcmp(name_buf, g_spawn_suspend_target) == 0) {
                    PRINT_DEBUG("[spawn_suspend] Target '%s' matched process name. Stopping PID %d.\n", g_spawn_suspend_target, current->pid);
                    force_sig(SIGSTOP, current);
                }
                spin_unlock(&g_suspend_lock);
            }
        } else {
            spin_unlock(&g_suspend_lock);
        }
    }

    return original_sys_prctl(regs);
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