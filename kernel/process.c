#include "process.h"
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/sched/mm.h>      // 包含 get_task_mm 的声明
#include <linux/sched/signal.h>  // 包含 find_get_pid 和 get_pid_task 的声明
#define ARC_PATH_MAX 256

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);
#endif

uintptr_t get_module_base(pid_t pid, char *name)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	uintptr_t base_addr = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	struct vma_iterator vmi;
#endif

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return 0;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return 0;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return 0;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma)
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
	{
		char buf[ARC_PATH_MAX];
		char *path_nm = "";

		if (vma->vm_file)
		{
			path_nm =
				file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
			if (!strcmp(kbasename(path_nm), name))
			{
				base_addr = vma->vm_start;
				break;
			}
		}
	}

	mmput(mm);
	return base_addr;
}

pid_t get_pid_by_name(const char *pname)
{
	struct task_struct *p;
	pid_t pid = 0;

	rcu_read_lock();
	for_each_process(p)
	{
		if (strcmp(p->comm, pname) == 0)
		{
			pid = p->pid;
			break;
		}
	}
	rcu_read_unlock();
	return pid;
}
