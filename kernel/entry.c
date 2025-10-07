#include <linux/module.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h> // For get_pid_task, find_get_pid
#include <linux/sched.h> // For get_cmdline
#include <linux/cred.h> // For current_euid()
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/mm.h> // Required for mmap
#include <linux/vmalloc.h> // Required for vmalloc
#include <linux/slab.h> // For kmalloc and kfree

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "anti_ptrace_detection.h" // Added
#include "thread.h"
#include "touch_input.h"
#include "single_step.h"
#include "spawn_suspend.h"
#include "register.h"
#include "mmu_breakpoint.h"
#include "syscall_trace.h"
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
static struct file_operations original_fops;
static struct file_operations hooked_fops;
static struct file *g_target_proc_file = NULL; // Keep the file open
static bool is_hijacked = false;

// Module unload control
static bool g_module_unloading = false;

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
        if (original_fops.unlocked_ioctl)
        {
            return original_fops.unlocked_ioctl(file, cmd, arg);
        }
        else
        {
            return -ENOTTY; // /proc/version has no ioctl, so this is the correct error.
        }
    }

    // --- If we reach here, the caller is the authenticated client ---
    
    // Dispatch to submodules first
    if (cmd >= OP_TOUCH_HOOK_INSTALL && cmd <= OP_TOUCH_CLEAN_STATE) {
        return handle_touch_ioctl(cmd, arg);
    }

	switch (cmd)
	{
	case OP_READ_MEM:
	{
		COPY_MEMORY *cm = kmalloc(sizeof(COPY_MEMORY), GFP_KERNEL);
		int ret = -1;
		if (!cm)
			return -ENOMEM;
		
		if (copy_from_user(cm, (void __user *)arg, sizeof(COPY_MEMORY)) != 0)
		{
			kfree(cm);
			return -1;
		}
		if (read_process_memory(cm->pid, cm->addr, cm->buffer, cm->size) == true)
		{
			ret = 0;
		}
		kfree(cm);
		return ret;
	}
	case OP_WRITE_MEM:
	{
		COPY_MEMORY *cm = kmalloc(sizeof(COPY_MEMORY), GFP_KERNEL);
		int ret = -1;
		if (!cm)
			return -ENOMEM;
		
		if (copy_from_user(cm, (void __user *)arg, sizeof(COPY_MEMORY)) != 0)
		{
			kfree(cm);
			return -1;
		}
		if (write_process_memory(cm->pid, cm->addr, cm->buffer, cm->size) == true)
		{
			ret = 0;
		}
		kfree(cm);
		return ret;
	}
	case OP_MODULE_BASE:
	{
		MODULE_BASE *mb = kmalloc(sizeof(MODULE_BASE), GFP_KERNEL);
		char *name = kmalloc(0x100, GFP_KERNEL);
		int ret = -1;
		
		if (!mb || !name) {
			kfree(mb);
			kfree(name);
			return -ENOMEM;
		}
		
		memset(name, 0, 0x100);
		
		if (copy_from_user(mb, (void __user *)arg, sizeof(MODULE_BASE)) != 0 || 
			copy_from_user(name, (void __user *)mb->name, 0x100 - 1) != 0)
		{
			kfree(mb);
			kfree(name);
			return -1;
		}
		
		mb->base = get_module_base(mb->pid, name);
		if (copy_to_user((void __user *)arg, mb, sizeof(MODULE_BASE)) == 0)
		{
			ret = 0;
		}
		
		kfree(mb);
		kfree(name);
		return ret;
	}
	case OP_HIDE_PROC:
	{
		HIDE_PROC *hp = kmalloc(sizeof(HIDE_PROC), GFP_KERNEL);
		int ret = -1;
		if (!hp)
			return -ENOMEM;
		
		if (copy_from_user(hp, (void __user *)arg, sizeof(HIDE_PROC)) != 0)
		{
			kfree(hp);
			return -1;
		}
		
		switch (hp->action)
		{
		case ACTION_HIDE:
			add_hidden_pid(hp->pid);
			ret = 0;
			break;
		case ACTION_UNHIDE:
			remove_hidden_pid(hp->pid);
			ret = 0;
			break;
		case ACTION_CLEAR:
			clear_hidden_pids();
			ret = 0;
			break;
		default:
			ret = -1;
			break;
		}
		kfree(hp);
		return ret;
	}

	case OP_READ_MEM_SAFE:
	{
		COPY_MEMORY *cm = kmalloc(sizeof(COPY_MEMORY), GFP_KERNEL);
		int ret = -1;
		if (!cm)
			return -ENOMEM;
		
		if (copy_from_user(cm, (void __user *)arg, sizeof(COPY_MEMORY)) != 0)
		{
			kfree(cm);
			return -1;
		}
		if (read_process_memory_safe(cm->pid, cm->addr, cm->buffer, cm->size) == true)
		{
			ret = 0;
		}
		kfree(cm);
		return ret;
	}
	case OP_GET_MEM_SEGMENTS:
    {
        GET_MEM_SEGMENTS *gms = kmalloc(sizeof(GET_MEM_SEGMENTS), GFP_KERNEL);
        int ret = -EFAULT;
        if (!gms)
            return -ENOMEM;
        
        if (copy_from_user(gms, (void __user *)arg, sizeof(GET_MEM_SEGMENTS)) != 0)
        {
            kfree(gms);
            return -EFAULT;
        }

        if (get_process_memory_segments(gms->pid, (PMEM_SEGMENT_INFO)gms->buffer, &gms->count) == 0)
        {
            if (copy_to_user((void __user *)arg, gms, sizeof(GET_MEM_SEGMENTS)) == 0)
            {
                ret = 0;
            }
        }
        
        kfree(gms);
        return ret;
	}

    case OP_ANTI_PTRACE_CTL:
    {
        ANTI_PTRACE_CTL *apc = kmalloc(sizeof(ANTI_PTRACE_CTL), GFP_KERNEL);
        int ret = -EFAULT;
        if (!apc)
            return -ENOMEM;
        
        if (copy_from_user(apc, (void __user *)arg, sizeof(ANTI_PTRACE_CTL)) != 0)
        {
            kfree(apc);
            return -EFAULT;
        }
        
        if (apc->action == ANTI_PTRACE_ENABLE) {
            start_anti_ptrace_detection();
            ret = 0;
        } else {
            stop_anti_ptrace_detection();
            ret = 0;
        }
        
        kfree(apc);
        return ret;
    }
    case OP_ENUM_THREADS:
    {
        ENUM_THREADS *et = kmalloc(sizeof(ENUM_THREADS), GFP_KERNEL);
        int ret = -EFAULT;
        if (!et)
            return -ENOMEM;
        
        if (copy_from_user(et, (void __user *)arg, sizeof(ENUM_THREADS)) != 0)
        {
            kfree(et);
            return -EFAULT;
        }
        
        if (handle_enum_threads(et) == 0)
        {
            if (copy_to_user((void __user *)arg, et, sizeof(ENUM_THREADS)) == 0)
            {
                ret = 0;
            }
        }
        
        kfree(et);
        return ret;
    }
    case OP_THREAD_CTL:
    {
        THREAD_CTL *tc = kmalloc(sizeof(THREAD_CTL), GFP_KERNEL);
        int ret = -EFAULT;
        if (!tc)
            return -ENOMEM;
        
        if (copy_from_user(tc, (void __user *)arg, sizeof(THREAD_CTL)) != 0)
        {
            kfree(tc);
            return -EFAULT;
        }
        
        if (handle_thread_control(tc) == 0)
        {
            ret = 0;
        }
        
        kfree(tc);
        return ret;
    }
    case OP_SINGLE_STEP_CTL:
    {
        SINGLE_STEP_CTL *ssc = kmalloc(sizeof(SINGLE_STEP_CTL), GFP_KERNEL);
        int ret = -EFAULT;
        if (!ssc)
            return -ENOMEM;
        
        if (copy_from_user(ssc, (void __user *)arg, sizeof(SINGLE_STEP_CTL)) != 0)
        {
            kfree(ssc);
            return -EFAULT;
        }

        // Debug: print raw bytes received
        {
            unsigned char *bytes = (unsigned char *)ssc;
            PRINT_DEBUG("[single_step] Received %zu bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        sizeof(SINGLE_STEP_CTL),
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7],
                        bytes[8], bytes[9], bytes[10], bytes[11],
                        bytes[12], bytes[13], bytes[14], bytes[15]);
        }

        if (handle_single_step_control(ssc) == 0)
        {
            ret = 0;
        }
        
        kfree(ssc);
        return ret;
    }
    case OP_SET_SPAWN_SUSPEND:
    {
        SPAWN_SUSPEND_CTL *spawn_ctl = kmalloc(sizeof(SPAWN_SUSPEND_CTL), GFP_KERNEL);
        int ret = -EFAULT;
        if (!spawn_ctl)
            return -ENOMEM;
        
        if (copy_from_user(spawn_ctl, (void __user *)arg, sizeof(SPAWN_SUSPEND_CTL)) != 0)
        {
            kfree(spawn_ctl);
            return -EFAULT;
        }
        
        set_spawn_suspend_target(spawn_ctl->target_name, spawn_ctl->enable);
        ret = 0;
        kfree(spawn_ctl);
        return ret;
    }
    case OP_RESUME_PROCESS:
    {
        RESUME_PROCESS_CTL *resume_ctl = kmalloc(sizeof(RESUME_PROCESS_CTL), GFP_KERNEL);
        struct task_struct *task;
        int ret = -EFAULT;
        if (!resume_ctl)
            return -ENOMEM;
        
        if (copy_from_user(resume_ctl, (void __user *)arg, sizeof(RESUME_PROCESS_CTL)) != 0)
        {
            kfree(resume_ctl);
            return -EFAULT;
        }
        
        task = get_pid_task(find_get_pid(resume_ctl->pid), PIDTYPE_PID);
        if (!task) {
            kfree(resume_ctl);
            return -ESRCH;
        }
        
        // Send SIGCONT to resume the process
        send_sig_info(SIGCONT, SEND_SIG_FORCED, task);
        put_task_struct(task);
        PRINT_DEBUG("[+] Sent SIGCONT to PID %d.\n", resume_ctl->pid);
        ret = 0;
        kfree(resume_ctl);
        return ret;
    }
    case OP_REG_ACCESS:
    {
        REG_ACCESS *reg_access = kmalloc(sizeof(REG_ACCESS), GFP_KERNEL);
        int ret = -EFAULT;
        if (!reg_access)
            return -ENOMEM;
        
        if (copy_from_user(reg_access, (void __user *)arg, sizeof(REG_ACCESS)) != 0)
        {
            kfree(reg_access);
            return -EFAULT;
        }
        
        if (handle_register_access(reg_access) == 0)
        {
            ret = 0;
        }
        
        kfree(reg_access);
        return ret;
    }
    
    case OP_MMU_BP_CTL:
    {
        MMU_BP_CTL *mbp = kmalloc(sizeof(MMU_BP_CTL), GFP_KERNEL);
        int ret = -EFAULT;
        if (!mbp)
            return -ENOMEM;
        
        if (copy_from_user(mbp, (void __user *)arg, sizeof(MMU_BP_CTL)) != 0)
        {
            kfree(mbp);
            return -EFAULT;
        }
        
        ret = handle_mmu_breakpoint_control(mbp);
        kfree(mbp);
        return ret;
    }
    case OP_MMU_BP_LIST:
    {
        // 参数结构：pid (输入), buffer (输出), count (输入/输出)
        struct {
            pid_t pid;
            uintptr_t buffer;
            size_t count;
        } *bp_list = kmalloc(sizeof(*bp_list), GFP_KERNEL);
        int ret = -EFAULT;
        if (!bp_list)
            return -ENOMEM;
        
        if (copy_from_user(bp_list, (void __user *)arg, sizeof(*bp_list)) != 0)
        {
            kfree(bp_list);
            return -EFAULT;
        }
        
        ret = handle_mmu_breakpoint_list(bp_list->pid, (PMMU_BP_INFO)bp_list->buffer, &bp_list->count);
        if (ret == 0) {
            // 更新count为实际找到的断点数量
            if (copy_to_user((void __user *)arg, bp_list, sizeof(*bp_list)) != 0) {
                ret = -EFAULT;
            }
        }
        
        kfree(bp_list);
        return ret;
    }
    case OP_UNLOAD_MODULE:
    {
        PRINT_DEBUG("[+] Unload module requested by PID %d\n", current->pid);
        
        // Set the unloading flag
        g_module_unloading = true;
        
        // Reset client PID to allow cleanup
        mutex_lock(&auth_mutex);
        client_pid = 0;
        mutex_unlock(&auth_mutex);
        
        // Perform cleanup
        _driver_cleanup();
        
        // Restore module visibility
        mutex_lock(&module_mutex);
        if (list_empty(&THIS_MODULE->list)) {
            list_add_tail(&THIS_MODULE->list, &THIS_MODULE->mkobj.kobj.entry);
        }
        mutex_unlock(&module_mutex);
        
        // Restore sysfs entry if needed
        if (!THIS_MODULE->mkobj.kobj.state_in_sysfs) {
            // Note: Full restoration might require more complex handling
            // For now, we at least make the module visible to lsmod
            PRINT_DEBUG("[+] Module made visible for unload\n");
        }
        
        // Return success - the actual unload will happen through normal module mechanism
        return 0;
    }
    case OP_SYSCALL_TRACE_CTL:
    {
        SYSCALL_TRACE_CTL *stc = kmalloc(sizeof(SYSCALL_TRACE_CTL), GFP_KERNEL);
        int ret = -EFAULT;
        if (!stc)
            return -ENOMEM;
        
        if (copy_from_user(stc, (void __user *)arg, sizeof(SYSCALL_TRACE_CTL)) != 0)
        {
            kfree(stc);
            return -EFAULT;
        }
        
        ret = handle_syscall_trace_control(stc);
        kfree(stc);
        return ret;
    }
    case OP_SYSCALL_TRACE_LIST:
    {
        // TODO: 实现事件列表获取
        return -ENOSYS;
    }
	default:
		return -EINVAL; // Unrecognized command for our driver
	}
	return 0;
}

static int dispatch_mmap(struct file *filp, struct vm_area_struct *vma)
{
    // Only our authenticated client can mmap
    if (current->tgid != client_pid || client_pid == 0) {
        // For any other process, fall back to original behavior (which is likely NULL/unsupported)
        if (original_fops.mmap) {
            return original_fops.mmap(filp, vma);
        }
        return -ENODEV;
    }

    // Pass the request to our touch input handler
    return touch_input_mmap(filp, vma);
}

int __init driver_entry(void)
{
	int ret;
    const struct file_operations *fops;

	PRINT_DEBUG("[+] driver_entry");

	ret = khook_init();
	if (ret)
	{
		PRINT_DEBUG("[-] kernel inline hook init failed\n");
		return ret;
	}

	// --- Hijack Logic (Refactored for mmap support) ---
	PRINT_DEBUG("[+] Hijacking f_op for %s\n", TARGET_FILE);
	g_target_proc_file = filp_open(TARGET_FILE, O_RDONLY, 0);
	if (IS_ERR(g_target_proc_file)) {
		PRINT_DEBUG("[-] Failed to open target file %s\n", TARGET_FILE);
		khook_exit();
		return PTR_ERR(g_target_proc_file);
	}

    fops = g_target_proc_file->f_op;
    if (!fops) {
        PRINT_DEBUG("[-] Target file %s has no file_operations\n", TARGET_FILE);
        filp_close(g_target_proc_file, NULL);
        khook_exit();
        return -EFAULT;
    }

    // Backup original fops and create our hooked version
    memcpy(&original_fops, fops, sizeof(struct file_operations));
    memcpy(&hooked_fops, fops, sizeof(struct file_operations));

    // Replace the operations we want to control
    hooked_fops.unlocked_ioctl = dispatch_ioctl;
    hooked_fops.mmap = dispatch_mmap;

    // Atomically replace the f_op pointer
    g_target_proc_file->f_op = &hooked_fops;
	
    is_hijacked = true;
	PRINT_DEBUG("[+] Successfully hijacked f_op for %s\n", TARGET_FILE);

#ifdef CONFIG_HIDE_PROC_MODE
	ret = hide_proc_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}
#endif

#ifdef CONFIG_HIDE_PROC_MODE
	ret = hide_kill_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}
#endif

#ifdef CONFIG_SINGLE_STEP_MODE
	ret = single_step_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}
#endif

#ifdef CONFIG_SPAWN_SUSPEND_MODE
	ret = spawn_suspend_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}
#endif

#ifdef CONFIG_MMU_BREAKPOINT_MODE
	ret = mmu_breakpoint_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}
#endif

#ifdef CONFIG_SYSCALL_TRACE_MODE
	ret = syscall_trace_init();
	if (ret)
	{
		_driver_cleanup();
		return ret;
	}
#endif

#ifdef CONFIG_TOUCH_INPUT_MODE
    ret = touch_input_init();
    if (ret)
    {
        _driver_cleanup();
        return ret;
    }
#endif

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

	// --- Restore Logic (Refactored) ---
	if (is_hijacked && g_target_proc_file) {
        PRINT_DEBUG("[+] Restoring original f_op for %s\n", TARGET_FILE);
        g_target_proc_file->f_op = &original_fops;
        filp_close(g_target_proc_file, NULL);
        g_target_proc_file = NULL;
	}
    
    // Cleanup our subsystems
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
    stop_anti_ptrace_detection(); // Ensure it's off on unload
#endif
#ifdef CONFIG_SPAWN_SUSPEND_MODE
    spawn_suspend_exit();
#endif
#ifdef CONFIG_SINGLE_STEP_MODE
    single_step_exit();
#endif
#ifdef CONFIG_MMU_BREAKPOINT_MODE
    mmu_breakpoint_exit();
#endif
#ifdef CONFIG_HIDE_PROC_MODE
	hide_kill_exit();
	hide_proc_exit();
#endif
#ifdef CONFIG_SYSCALL_TRACE_MODE
	syscall_trace_exit();
#endif
#ifdef CONFIG_TOUCH_INPUT_MODE
    touch_input_exit();
#endif
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
