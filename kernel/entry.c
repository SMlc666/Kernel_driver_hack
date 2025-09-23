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

// --- Globals for mmap hijack ---
static int (*original_proc_version_mmap)(struct file *, struct vm_area_struct *);
static void *shared_mem = NULL; // Generic pointer for our shared memory

// A simple struct for our test
struct TestSharedMemory {
    volatile uint64_t magic_value;
};

#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "touch.h"
#include "touch_control.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/utils/p_memory.h"
#include "version_control.h"
#include "touch_shared.h"

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

// --- mmap hijack implementation ---
static int hijacked_proc_version_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pfn;
	size_t shared_mem_size = PAGE_ALIGN(sizeof(struct SharedTouchMemory));

    PRINT_DEBUG("[+] Hijacked mmap called by PID %d for size %lu\n", current->pid, size);

    if (current->tgid != client_pid || client_pid == 0) {
        if (original_proc_version_mmap) {
            return original_proc_version_mmap(filp, vma);
        }
        return -ENODEV;
    }

    if (size > shared_mem_size) {
		PRINT_DEBUG("[-] mmap request size (%lu) is larger than allocated size (%zu)\n", size, shared_mem_size);
		return -EINVAL;
	}

    pfn = vmalloc_to_pfn(shared_mem);
    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
        PRINT_DEBUG("[-] remap_pfn_range failed in hijacked_mmap\n");
        return -EAGAIN;
    }

    vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
    PRINT_DEBUG("[+] Shared memory mapped successfully via hijack.\n");
    return 0;
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
	// --- New Touch Control IOCTLs ---
	case OP_HOOK_INPUT_DEVICE:
	{
		HOOK_INPUT_DEVICE_DATA hidd;
		if (copy_from_user(&hidd, (void __user *)arg, sizeof(hidd)) != 0) {
			return -EFAULT;
		}
		if (touch_control_start_hijack(hidd.name) != 0) {
			return -EINVAL; // Hook failed
		}
		break;
	}
	case OP_UNHOOK_INPUT_DEVICE:
	{
		touch_control_stop_hijack();
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
    void *hijacked_mmap_ptr = &hijacked_proc_version_mmap;
	size_t shared_mem_size = sizeof(struct SharedTouchMemory);
	unsigned long addr;

	PRINT_DEBUG("[+] driver_entry");

    // Allocate shared memory for mmap
    shared_mem = vmalloc(shared_mem_size);
    if (!shared_mem) {
        PRINT_DEBUG("[-] Failed to vmalloc shared memory\n");
        return -ENOMEM;
    }
	for (addr = (unsigned long)shared_mem; addr < (unsigned long)shared_mem + shared_mem_size; addr += PAGE_SIZE) {
        SetPageReserved(vmalloc_to_page((void *)addr));
    }
    memset(shared_mem, 0, shared_mem_size);
    PRINT_DEBUG("[+] Shared memory allocated at %p (size: %zu)\n", shared_mem, shared_mem_size);




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
    original_proc_version_mmap = proc_version_fops->mmap;

	if (remap_write_range(&proc_version_fops->unlocked_ioctl, &dispatch_ioctl_ptr, sizeof(void *), true)) {
        PRINT_DEBUG("[-] Failed to hook unlocked_ioctl for %s\n", TARGET_FILE);
        khook_exit();
        return -EFAULT;
    }

	if (remap_write_range(&proc_version_fops->mmap, &hijacked_mmap_ptr, sizeof(void *), true)) {
        PRINT_DEBUG("[-] Failed to hook mmap for %s\n", TARGET_FILE);
        // Restore ioctl on failure
        remap_write_range(&proc_version_fops->unlocked_ioctl, &original_ioctl, sizeof(void *), true);
        khook_exit();
        return -EFAULT;
    }
	
is_hijacked = true;
	PRINT_DEBUG("[+] Successfully hooked unlocked_ioctl and mmap for %s\n", TARGET_FILE);

    // Initialize our subsystems
    touch_control_init(shared_mem);

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
		PRINT_DEBUG("[+] Restoring original operations for %s\n", TARGET_FILE);
		
		if (proc_version_fops) {
            // Restore mmap first
            if (remap_write_range(&proc_version_fops->mmap, &original_proc_version_mmap, sizeof(void *), true)) {
                PRINT_DEBUG("[-] Failed to restore mmap for %s\n", TARGET_FILE);
            } else {
                PRINT_DEBUG("[+] Successfully restored mmap.\n");
            }

            // Then restore ioctl
            if (remap_write_range(&proc_version_fops->unlocked_ioctl, &original_ioctl_ptr, sizeof(void *), true)) {
                PRINT_DEBUG("[-] Failed to restore unlocked_ioctl for %s\n", TARGET_FILE);
            } else {
                PRINT_DEBUG("[+] Successfully restored unlocked_ioctl.\n");
            }
        }
	}
    
    // Free shared memory
    if (shared_mem) {
		unsigned long addr;
		size_t shared_mem_size = sizeof(struct SharedTouchMemory);
		for (addr = (unsigned long)shared_mem; addr < (unsigned long)shared_mem + shared_mem_size; addr += PAGE_SIZE) {
	        ClearPageReserved(vmalloc_to_page((void *)addr));
	    }
        vfree(shared_mem);
        shared_mem = NULL;
        PRINT_DEBUG("[+] Shared memory freed.\n");
    }
    
    
    // Cleanup our subsystems
    touch_control_exit();

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