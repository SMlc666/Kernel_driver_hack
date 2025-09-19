#include <linux/module.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h> // For get_pid_task, find_get_pid

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "touch.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/utils/p_memory.h"

// --- Start of Hijack Logic ---

#define TARGET_FILE "/proc/version"

// Forward declaration
static void _driver_cleanup(void);

// State management
static pid_t client_pid = 0;
static DEFINE_MUTEX(auth_mutex); // Mutex to protect client_pid

// --- Hijack State ---
// Pointers for original and hooked operations
static long (*original_ioctl)(struct file *, unsigned int, unsigned long) = NULL;
static struct file_operations *proc_version_fops = NULL;
static bool is_hijacked = false;

// --- End of Hijack Logic ---

int dispatch_open(struct inode *node, struct file *file)
{
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	return 0;
}

// Helper to check if a PID is alive
bool is_pid_alive(pid_t pid)
{
    struct task_struct *task;
    if (pid <= 0) return false;
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (task) {
        put_task_struct(task);
        return true;
    }
    return false;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
    // Move declarations to the top of the function block to comply with C90
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
    
    printk(KERN_INFO "[+] dispatch_ioctl called by PID %d with cmd: 0x%x\n", current->pid, cmd);

	// --- Authentication and Authorization Logic ---
    if (cmd == OP_AUTHENTICATE)
    {

        mutex_lock(&auth_mutex);
        // Check if there is an existing, live client
        if (client_pid != 0 && is_pid_alive(client_pid)) {
            mutex_unlock(&auth_mutex);
            return -ENOTTY; // Another client is active, pretend we don't support ioctl
        }
        // Set new client
        client_pid = current->pid;
        mutex_unlock(&auth_mutex);
        printk(KERN_INFO "[+] Client authenticated with PID: %d\n", client_pid);
        return 0;
    }

    // If not authenticating, check if the caller is the authenticated client
    if (current->pid != client_pid || client_pid == 0)
    {
        // Not the client, or no client is connected. Behave like the original file.
        if (original_ioctl)
        {
            return original_ioctl(file, cmd, arg);
        }
        else
        {
            return -ENOTTY; // /proc/version has no ioctl, so this is the correct error.
        }
    }

    // --- If we reach here, the caller is the authenticated client ---
	switch (cmd)
	{
	case OP_READ_MEM:
	{
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
		{
			return -1;
		}
		if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
		{
			return -1;
		}
		break;
	}
	case OP_WRITE_MEM:
	{
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
		{
			return -1;
		}
		if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
		{
			return -1;
		}
		break;
	}
	case OP_MODULE_BASE:
	{
        char name[0x100] = {0};
		if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
		{
			return -1;
		}
		mb.base = get_module_base(mb.pid, name);
		if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
		{
			return -1;
		}
		break;
	}
	case OP_HIDE_PROC:
	{
		static HIDE_PROC hp;
		if (copy_from_user(&hp, (void __user *)arg, sizeof(hp)) != 0)
		{
			return -1;
		}
		switch (hp.action)
		{
		case ACTION_HIDE:
			add_hidden_pid(hp.pid);
			break;
		case ACTION_UNHIDE:
			remove_hidden_pid(hp.pid);
			break;
		case ACTION_CLEAR:
			clear_hidden_pids();
			break;
		default:
			return -1;
		}
		break;
	}
	case OP_TOUCH_INIT:
	{
		static TOUCH_INIT_DATA tid;
		if (copy_from_user(&tid, (void __user *)arg, sizeof(tid)) != 0)
		{
			return -1;
		}
		if (touch_init(&tid) != 0)
		{
			return -1;
		}
		break;
	}
	case OP_TOUCH_SEND:
	{
		static TOUCH_DATA td;
		if (copy_from_user(&td, (void __user *)arg, sizeof(td)) != 0)
		{
			return -1;
		}
		touch_send_event(&td);
		break;
	}
	case OP_TOUCH_DEINIT:
	{
		touch_deinit();
		break;
	}
	
default:
		return -EINVAL; // Unrecognized command for our driver
	}
	return 0;
}

int __init driver_entry(void)
{
	int ret;
	struct file *target_file;
    struct inode *target_inode;
    void *dispatch_ioctl_ptr = &dispatch_ioctl;

	printk("[+] driver_entry");

	ret = khook_init();
	if (ret)
	{
		printk("[-] kernel inline hook init failed\n");
		return ret;
	}

	// --- Hijack Logic (Corrected) ---
	printk(KERN_INFO "[+] Hijacking ioctl for %s\n", TARGET_FILE);
	target_file = filp_open(TARGET_FILE, O_RDONLY, 0);
	if (IS_ERR(target_file)) {
		printk(KERN_ERR "[-] Failed to open target file %s\n", TARGET_FILE);
		khook_exit();
		return PTR_ERR(target_file);
	}

    target_inode = file_inode(target_file);
    if (!target_inode) {
        printk(KERN_ERR "[-] Failed to get inode for %s\n", TARGET_FILE);
        filp_close(target_file, NULL);
        khook_exit();
        return -EFAULT;
    }

	proc_version_fops = (struct file_operations *)target_inode->i_fop;
    filp_close(target_file, NULL); // Close the file, we have the fops pointer.

	if (!proc_version_fops) {
		printk(KERN_ERR "[-] Target file %s has no file_operations\n", TARGET_FILE);
		khook_exit();
		return -EFAULT;
	}

    original_ioctl = proc_version_fops->unlocked_ioctl;

	if (remap_write_range(&proc_version_fops->unlocked_ioctl, &dispatch_ioctl_ptr, sizeof(void *), true)) {
        printk(KERN_ERR "[-] Failed to hook unlocked_ioctl for %s\n", TARGET_FILE);
        khook_exit();
        return -EFAULT;
    }
	
is_hijacked = true;
	printk(KERN_INFO "[+] Successfully hooked unlocked_ioctl for %s\n", TARGET_FILE);

	ret = hide_proc_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}

	ret = hide_kill_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}

	mutex_lock(&module_mutex);
	list_del_init(&THIS_MODULE->list);
	mutex_unlock(&module_mutex);
	printk(KERN_INFO "[+] Module hidden from lsmod\n");

    if (THIS_MODULE->mkobj.kobj.state_in_sysfs) {
        kobject_del(&THIS_MODULE->mkobj.kobj);
        printk(KERN_INFO "[+] Module sysfs entry hidden\n");
    }

	return 0;
}

static void _driver_cleanup(void)
{
	printk("[+] driver_unload");

	// --- Restore Logic (Corrected) ---
	if (is_hijacked) {
        void *original_ioctl_ptr = &original_ioctl;
		printk(KERN_INFO "[+] Restoring original unlocked_ioctl for %s\n", TARGET_FILE);
		
		if (proc_version_fops && remap_write_range(&proc_version_fops->unlocked_ioctl, &original_ioctl_ptr, sizeof(void *), true)) {
            printk(KERN_ERR "[-] Failed to restore unlocked_ioctl for %s\n", TARGET_FILE);
        } else {
            printk(KERN_INFO "[+] Successfully restored unlocked_ioctl for %s\n", TARGET_FILE);
        }
	}
    
    

	touch_deinit();
	hide_kill_exit();
	hide_proc_exit();
	khook_exit();
    
    // Reset client PID on unload for safety
    mutex_lock(&auth_mutex);
    client_pid = 0;
    mutex_unlock(&auth_mutex);
}

void __exit driver_unload(void)
{
	_driver_cleanup();
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");
