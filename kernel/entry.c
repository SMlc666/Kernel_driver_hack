#include <linux/module.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h> // For get_pid_task, find_get_pid
#include <linux/cred.h> // For current_euid()
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/mm.h> // Required for mmap
#include <linux/vmalloc.h> // Required for vmalloc

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "anti_ptrace_detection.h" // Added
#include "thread.h"
#include "single_step.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/utils/p_memory.h"
#include "version_control.h"

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
	static GET_PID gp;
	static GET_MEM_SEGMENTS gms;
    static HIDE_PROC hp;
    static ANTI_PTRACE_CTL apc;
    static GET_ALL_PROCS gap;
    static ENUM_THREADS et;
    static THREAD_CTL tc;
    static SINGLE_STEP_CTL ssc;
    
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

        // Force-cleanup any stale single-step session from a previous client
        if (g_target_tid != 0) {
            PRINT_DEBUG("[+] Forcibly cleaning up stale single-step session for TID %d\n", g_target_tid);
            single_step_exit(); 
        }

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
	case OP_GET_MEM_SEGMENTS:
    {
        if (copy_from_user(&gms, (void __user *)arg, sizeof(gms)) != 0)
        {
            return -EFAULT;
        }

        if (get_process_memory_segments(gms.pid, (PMEM_SEGMENT_INFO)gms.buffer, &gms.count) != 0)
        {
            return -EFAULT;
        }

		if (copy_to_user((void __user *)arg, &gms, sizeof(gms)) != 0)
		{
			return -EFAULT;
		}
		break;
	}
	case OP_GET_ALL_PROCS:
	{
		if (copy_from_user(&gap, (void __user *)arg, sizeof(gap)) != 0)
		{
			return -EFAULT;
		}
		if (get_all_processes((PPROCESS_INFO)gap.buffer, &gap.count) != 0)
		{
			return -EFAULT;
		}
		if (copy_to_user((void __user *)arg, &gap, sizeof(gap)) != 0)
		{
			return -EFAULT;
		}
		break;
	}
    case OP_ANTI_PTRACE_CTL:
    {
        if (copy_from_user(&apc, (void __user *)arg, sizeof(apc)) != 0)
        {
            return -EFAULT;
        }
        if (apc.action == ANTI_PTRACE_ENABLE) {
            start_anti_ptrace_detection();
        } else {
            stop_anti_ptrace_detection();
        }
        break;
    }
    case OP_ENUM_THREADS:
    {
        if (copy_from_user(&et, (void __user *)arg, sizeof(et)) != 0)
        {
            return -EFAULT;
        }
        if (handle_enum_threads(&et) != 0)
        {
            return -EFAULT;
        }
        if (copy_to_user((void __user *)arg, &et, sizeof(et)) != 0)
        {
            return -EFAULT;
        }
        break;
    }
    case OP_THREAD_CTL:
    {
        if (copy_from_user(&tc, (void __user *)arg, sizeof(tc)) != 0)
        {
            return -EFAULT;
        }
        if (handle_thread_control(&tc) != 0)
        {
            return -EFAULT;
        }
        break;
    }
    case OP_SINGLE_STEP_CTL:
    {
        if (copy_from_user(&ssc, (void __user *)arg, sizeof(ssc)) != 0)
        {
            return -EFAULT;
        }

        // Debug: print raw bytes received
        {
            unsigned char *bytes = (unsigned char *)&ssc;
            PRINT_DEBUG("[single_step] Received %zu bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        sizeof(ssc),
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7],
                        bytes[8], bytes[9], bytes[10], bytes[11],
                        bytes[12], bytes[13], bytes[14], bytes[15]);
        }

        if (handle_single_step_control(&ssc) != 0)
        {
            return -EFAULT;
        }
        // GET_INFO action needs to write back register info
        if (ssc.action == STEP_ACTION_GET_INFO) {
             if (copy_to_user((void __user *)arg, &ssc, sizeof(ssc)) != 0)
             {
                 return -EFAULT;
             }
        }
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

	ret = single_step_init();
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
		PRINT_DEBUG("[+] Restoring original operations for %s\n", TARGET_FILE);
		
		if (proc_version_fops) {
            if (remap_write_range(&proc_version_fops->unlocked_ioctl, &original_ioctl_ptr, sizeof(void *), true)) {
                PRINT_DEBUG("[-] Failed to restore unlocked_ioctl for %s\n", TARGET_FILE);
            } else {
                PRINT_DEBUG("[+] Successfully restored unlocked_ioctl.\n");
            }
        }
	}
    
    // Cleanup our subsystems
    stop_anti_ptrace_detection(); // Ensure it's off on unload
    single_step_exit();
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
