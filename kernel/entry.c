#include <linux/module.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/utils/p_memory.h"

// --- Start of Advanced Hijack Logic ---

#define TARGET_FILE "/proc/version"

// State management
static pid_t client_pid = 0;
static DEFINE_MUTEX(auth_mutex); // Mutex to protect client_pid

// Backup for the original file_operations and ioctl
static struct file_operations *original_fops;
static long (*original_ioctl)(struct file *, unsigned int, unsigned long);
static struct file_operations hijacked_fops;
static bool is_hijacked = false;

// --- Tracepoint Handler ---
static void process_exit_probe(void *data, struct task_struct *p)
{
    // Check if the exiting process is our client
    if (p->pid == client_pid)
    {
        mutex_lock(&auth_mutex);
        client_pid = 0; // Reset the client PID
        mutex_unlock(&auth_mutex);
        printk(KERN_INFO "[+] Client PID %d exited. Resetting state.\n", p->pid);
    }
}

// --- End of Advanced Hijack Logic ---

int dispatch_open(struct inode *node, struct file *file)
{
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
	// --- Authentication and Authorization Logic ---
    if (cmd == OP_AUTHENTICATE)
    {
        mutex_lock(&auth_mutex);
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
	static COPY_MEMORY cm;
	static MODULE_BASE mb;

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
	
default:
        // Other commands like OP_INIT_KEY might be handled here if needed
		return -EINVAL; // Unrecognized command for our driver
	}
	return 0;
}

int __init driver_entry(void)
{
	int ret;
	struct file *target_file;
	printk("[+] driver_entry");

	ret = khook_init();
	if (ret)
	{
		printk("[-] kernel inline hook init failed\n");
		return ret;
	}

    // --- Register Tracepoint ---
    ret = tracepoint_probe_register("sched_process_exit", (void *)process_exit_probe, NULL);
    if (ret) {
        printk(KERN_ERR "[-] Failed to register tracepoint\n");
        khook_exit();
        return ret;
    }
    printk(KERN_INFO "[+] sched_process_exit tracepoint registered.\n");

	// --- Hijack Logic ---
	printk(KERN_INFO "[+] Hijacking %s\n", TARGET_FILE);
	target_file = filp_open(TARGET_FILE, O_RDONLY, 0);
	if (IS_ERR(target_file)) {
		printk(KERN_ERR "[-] Failed to open target file %s\n", TARGET_FILE);
        tracepoint_probe_unregister("sched_process_exit", (void *)process_exit_probe, NULL);
		khook_exit();
		return PTR_ERR(target_file);
	}

	original_fops = (struct file_operations *)target_file->f_op;
	if (!original_fops) {
		printk(KERN_ERR "[-] Target file %s has no file_operations\n", TARGET_FILE);
		filp_close(target_file, NULL);
        tracepoint_probe_unregister("sched_process_exit", (void *)process_exit_probe, NULL);
		khook_exit();
		return -EFAULT;
	}

    // Backup original ioctl specifically
    original_ioctl = original_fops->unlocked_ioctl;

	memcpy(&hijacked_fops, original_fops, sizeof(struct file_operations));
	hijacked_fops.owner = THIS_MODULE;
	hijacked_fops.unlocked_ioctl = dispatch_ioctl;

	if (remap_write_range((void *)&target_file->f_op, &hijacked_fops, sizeof(void *), true)) {
        printk(KERN_ERR "[-] Failed to overwrite f_op for %s\n", TARGET_FILE);
        filp_close(target_file, NULL);
        tracepoint_probe_unregister("sched_process_exit", (void *)process_exit_probe, NULL);
        khook_exit();
        return -EFAULT;
    }
	
is_hijacked = true;
	filp_close(target_file, NULL);
	printk(KERN_INFO "[+] Successfully hijacked file_operations for %s\n", TARGET_FILE);

	ret = hide_proc_init();
	if (ret)
	{
		driver_unload();
		return ret;
	}

	ret = hide_kill_init();
	if (ret)
	{
		driver_unload();
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

void __exit driver_unload(void)
{
	printk("[+] driver_unload");

	// --- Restore Logic ---
	if (is_hijacked) {
		struct file *target_file;
		printk(KERN_INFO "[+] Restoring original file_operations for %s\n", TARGET_FILE);
		
		target_file = filp_open(TARGET_FILE, O_RDONLY, 0);
		if (IS_ERR(target_file)) {
			printk(KERN_ERR "[-] Failed to open %s for restoration\n", TARGET_FILE);
		} else {
			if (remap_write_range((void *)&target_file->f_op, &original_fops, sizeof(void *), true)) {
				printk(KERN_ERR "[-] Failed to restore f_op for %s\n", TARGET_FILE);
			} else {
				printk(KERN_INFO "[+] Successfully restored f_op for %s\n", TARGET_FILE);
			}
			filp_close(target_file, NULL);
		}
	}
    
    // --- Unregister Tracepoint ---
    tracepoint_probe_unregister("sched_process_exit", (void *)process_exit_probe, NULL);
    printk(KERN_INFO "[+] sched_process_exit tracepoint unregistered.\n");

	hide_kill_exit();
	hide_proc_exit();
	khook_exit();
    
    // Reset client PID on unload for safety
    mutex_lock(&auth_mutex);
    client_pid = 0;
    mutex_unlock(&auth_mutex);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");