#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_proc.h"
#include "hide_kill.h"
#include "inline_hook/p_lkrg_main.h"

#define DEVICE_NAME "JiangNight"

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
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
	static char key[0x100] = {0};
	static char name[0x100] = {0};
	static bool is_verified = false;

	if (cmd == OP_INIT_KEY && !is_verified)
	{
		if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) != 0)
		{
			return -1;
		}
	}
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
		break;
	}
	return 0;
}

struct file_operations dispatch_functions = {
	.owner = THIS_MODULE,
	.open = dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &dispatch_functions,
};

int __init driver_entry(void)
{
	int ret;
	printk("[+] driver_entry");

	ret = khook_init();
	if (ret)
	{
		printk("[-] kernel inline hook init failed\n");
		return ret;
	}

	// Test for sys_call_table
	{
		unsigned long *sys_call_table_addr = NULL;
		
		// Declare the function since it's not in a header
		extern unsigned long * get_sys_call_table(void);

		printk(KERN_INFO "[KALLSYMS_TEST] Trying kallsyms_lookup_name first...\n");
		if (P_SYM(p_kallsyms_lookup_name)) {
			sys_call_table_addr = (unsigned long *)P_SYM(p_kallsyms_lookup_name)("sys_call_table");
		}

		if (sys_call_table_addr) {
			printk(KERN_INFO "[KALLSYMS_TEST] SUCCESS: Found sys_call_table via kallsyms_lookup_name at: %px\n", sys_call_table_addr);
		} else {
			printk(KERN_INFO "[KALLSYMS_TEST] INFO: kallsyms_lookup_name failed. Trying memory scan fallback...\n");
			sys_call_table_addr = get_sys_call_table();
			if (sys_call_table_addr) {
				printk(KERN_INFO "[KALLSYMS_TEST] SUCCESS: Found sys_call_table via memory scan at: %px\n", sys_call_table_addr);
			} else {
				printk(KERN_INFO "[KALLSYMS_TEST] FAILED: Memory scan also failed to find sys_call_table.\n");
			}
		}
	}

	ret = misc_register(&misc);
	if (ret)
	{
		khook_exit();
		return ret;
	}

	ret = hide_proc_init();
	if (ret)
	{
		misc_deregister(&misc);
		khook_exit();
		return ret;
	}

	ret = hide_kill_init();
	if (ret)
	{
		hide_proc_exit();
		misc_deregister(&misc);
		khook_exit();
		return ret;
	}

	// Hide module from lsmod
	mutex_lock(&module_mutex);
	list_del_init(&THIS_MODULE->list);
	mutex_unlock(&module_mutex);
	printk(KERN_INFO "[+] Module hidden from lsmod\n");

    // 尝试隐藏 /sys/module/<模块名> 目录
    if (THIS_MODULE->mkobj.kobj.state_in_sysfs) {
        kobject_del(&THIS_MODULE->mkobj.kobj);
        printk(KERN_INFO "[+] Module sysfs entry hidden\n");
    }

	return 0;
}

void __exit driver_unload(void)
{
	printk("[+] driver_unload");


	hide_kill_exit();
	hide_proc_exit();
	misc_deregister(&misc);
	khook_exit();
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JiangNight");


