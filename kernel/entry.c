#include <linux/module.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h> // For get_pid_task, find_get_pid
#include <linux/cred.h> // For current_euid()
#include <linux/timer.h>
#include <linux/jiffies.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "touch.h"
#include "event_hijack.h" // <-- Include our new header
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/utils/p_memory.h"
#include "version_control.h"

// --- Start of Hijack Logic ---

#define TARGET_FILE "/proc/version"

// --- Watchdog State ---
static struct timer_list watchdog_timer;
static unsigned long last_heartbeat_jiffies;
#define WATCHDOG_TIMEOUT (5 * HZ)

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

// --- Watchdog Callback ---
static void watchdog_callback(struct timer_list *t)
{
    if (!is_hook_active()) {
        // Hook is not active, no need for watchdog.
        return;
    }

    if (time_after(jiffies, last_heartbeat_jiffies + WATCHDOG_TIMEOUT)) {
        PRINT_DEBUG("[WATCHDOG] Client PID %d timed out. Cleaning up hook automatically.\n", client_pid);
        do_cleanup_hook(); // This will also wake up any waiting readers
        // Do not reschedule the timer.
    } else {
        // Client is still alive, check again later.
        mod_timer(&watchdog_timer, jiffies + msecs_to_jiffies(2000));
    }
}


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
	static GET_PID gp;
    
    PRINT_DEBUG("[+] dispatch_ioctl called by PID %d with cmd: 0x%x\n", current->pid, cmd);

	// Audit: Only allow root user
    if (current_euid().val != 0) {
        PRINT_DEBUG("[-] Non-root user (UID: %d) attempted to use the driver.\n", current_euid().val);
        return -ENOTTY;
    }

	// --- Authentication and Authorization Logic ---
    if (cmd == OP_AUTHENTICATE)
    {

        mutex_lock(&auth_mutex);
        // Check if there is an existing, live client
        if (client_pid != 0 && is_pid_alive(client_pid)) {
            mutex_unlock(&auth_mutex);
            return -ENOTTY; // Another client is active, pretend we don't support ioctl
        }
        // Set new client's thread group ID
        client_pid = current->tgid;
        mutex_unlock(&auth_mutex);
        PRINT_DEBUG("[+] Client authenticated with PID: %d\n", client_pid);
        return 0;
    }

    // If not authenticating, check if the caller is the authenticated client's thread group
    if (current->tgid != client_pid || client_pid == 0)
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
	case OP_GET_PID:
	{
		char name[TASK_COMM_LEN];
		if (copy_from_user(&gp, (void __user *)arg, sizeof(gp)) != 0)
		{
			return -1;
		}
		if (copy_from_user(name, (void __user *)gp.name, sizeof(name) - 1) != 0)
		{
			return -1;
		}
		name[sizeof(name) - 1] = '\0';
		gp.pid = get_pid_by_name(name);
		if (copy_to_user((void __user *)arg, &gp, sizeof(gp)) != 0)
		{
			return -1;
		}
		break;
	}
	case OP_TOUCH_SET_DEVICE:
	{
		// The argument 'arg' is a user-space pointer to the path string
		if (touch_set_device((const char __user *)arg) != 0)
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
	case OP_HOOK_INPUT_DEVICE_BY_NAME:
	{
		HOOK_INPUT_DEVICE_DATA hidd;
		PRINT_DEBUG("[+] In case OP_HOOK_INPUT_DEVICE_BY_NAME. Attempting copy_from_user.\n");
		if (copy_from_user(&hidd, (void __user *)arg, sizeof(hidd)) != 0)
		{
			PRINT_DEBUG("[-] copy_from_user failed!\n");
			return -EFAULT;
		}
		
		PRINT_DEBUG("[+] copy_from_user successful. Calling touch_set_device_by_name.\n");
		if (touch_set_device_by_name(hidd.name) != 0)
		{
			PRINT_DEBUG("[-] touch_set_device_by_name failed!\n");
			return -1;
		}
		PRINT_DEBUG("[+] touch_set_device_by_name successful.\n");
		break;
	}
	case OP_HOOK_INPUT_DEVICE:
	{
		HOOK_INPUT_DEVICE_DATA hidd;
		if (copy_from_user(&hidd, (void __user *)arg, sizeof(hidd)) != 0) {
			return -EFAULT;
		}
		if (do_hook_input_device(hidd.name) == 0) {
			// Hook successful, start the watchdog
			last_heartbeat_jiffies = jiffies;
			mod_timer(&watchdog_timer, jiffies + msecs_to_jiffies(2000));
		} else {
			return -EINVAL; // Hook failed
		}
		break;
	}
	case OP_UNHOOK_INPUT_DEVICE:
	{
		del_timer_sync(&watchdog_timer);
		do_cleanup_hook();
		break;
	}
	case OP_READ_INPUT_EVENTS:
	{
		return do_read_input_events((PEVENT_PACKAGE)arg);
	}
	case OP_INJECT_INPUT_EVENT:
	{
		return do_inject_input_event((struct input_event *)arg);
	}
	case OP_INJECT_INPUT_PACKAGE:
	{
		return do_inject_input_package((PEVENT_PACKAGE)arg);
	}
	case OP_HEARTBEAT:
	{
		last_heartbeat_jiffies = jiffies;
		break;
	}
	case OP_READ_MEM_SAFE:
	{
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
		{
			return -1;
		}
		if (read_process_memory_safe(cm.pid, cm.addr, cm.buffer, cm.size) == false)
		{
			return -1;
		}
		break;
	}
	case OP_SET_TOUCH_MODE:
	{
		int mode;
		if (copy_from_user(&mode, (void __user *)arg, sizeof(mode)) != 0)
		{
			return -EFAULT;
		}
		return do_set_touch_mode(mode);
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

	PRINT_DEBUG("[+] driver_entry");

	ret = khook_init();
	if (ret)
	{
		PRINT_DEBUG("[-] kernel inline hook init failed\n");
		return ret;
	}

	// --- Hijack Logic (Corrected) ---
	PRINT_DEBUG("[+] Hijacking ioctl for %s\n", TARGET_FILE);
	target_file = filp_open(TARGET_FILE, O_RDONLY, 0);
	if (IS_ERR(target_file)) {
		PRINT_DEBUG("[-] Failed to open target file %s\n", TARGET_FILE);
		khook_exit();
		return PTR_ERR(target_file);
	}

    target_inode = file_inode(target_file);
    if (!target_inode) {
        PRINT_DEBUG("[-] Failed to get inode for %s\n", TARGET_FILE);
        filp_close(target_file, NULL);
        khook_exit();
        return -EFAULT;
    }

	proc_version_fops = (struct file_operations *)target_inode->i_fop;
    filp_close(target_file, NULL); // Close the file, we have the fops pointer.

	if (!proc_version_fops) {
		PRINT_DEBUG("[-] Target file %s has no file_operations\n", TARGET_FILE);
		khook_exit();
		return -EFAULT;
	}

    original_ioctl = proc_version_fops->unlocked_ioctl;

	if (remap_write_range(&proc_version_fops->unlocked_ioctl, &dispatch_ioctl_ptr, sizeof(void *), true)) {
        PRINT_DEBUG("[-] Failed to hook unlocked_ioctl for %s\n", TARGET_FILE);
        khook_exit();
        return -EFAULT;
    }
	
is_hijacked = true;
	PRINT_DEBUG("[+] Successfully hooked unlocked_ioctl for %s\n", TARGET_FILE);

    // Initialize our subsystems
    event_hijack_init();
    timer_setup(&watchdog_timer, watchdog_callback, 0);

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
	PRINT_DEBUG("[+] Module hidden from lsmod\n");

    if (THIS_MODULE->mkobj.kobj.state_in_sysfs) {
        kobject_del(&THIS_MODULE->mkobj.kobj);
        PRINT_DEBUG("[+] Module sysfs entry hidden\n");
    }

	return 0;
}

static void _driver_cleanup(void)
{
	PRINT_DEBUG("[+] driver_unload");

	// --- Restore Logic (Corrected) ---
	if (is_hijacked) {
        void *original_ioctl_ptr = &original_ioctl;
		PRINT_DEBUG("[+] Restoring original unlocked_ioctl for %s\n", TARGET_FILE);
		
		if (proc_version_fops && remap_write_range(&proc_version_fops->unlocked_ioctl, &original_ioctl_ptr, sizeof(void *), true)) {
            PRINT_DEBUG("[-] Failed to restore unlocked_ioctl for %s\n", TARGET_FILE);
        } else {
            PRINT_DEBUG("[+] Successfully restored unlocked_ioctl for %s\n", TARGET_FILE);
        }
	}
    
    
    // Cleanup our subsystems
    del_timer_sync(&watchdog_timer);
    event_hijack_exit();

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