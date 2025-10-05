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

int get_process_memory_segments(pid_t pid, PMEM_SEGMENT_INFO user_buffer, size_t *count)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    size_t segments_found = 0;
    size_t buffer_capacity = *count;
    int ret = 0;

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (segments_found < buffer_capacity) {
            MEM_SEGMENT_INFO info;
            char *path_name;
            char path_buf[SEGMENT_PATH_MAX];

            info.start = vma->vm_start;
            info.end = vma->vm_end;
            info.flags = vma->vm_flags;
            memset(info.path, 0, SEGMENT_PATH_MAX);

            if (vma->vm_file) {
                path_name = file_path(vma->vm_file, path_buf, SEGMENT_PATH_MAX - 1);
                if (!IS_ERR(path_name)) {
                    strncpy(info.path, path_name, SEGMENT_PATH_MAX - 1);
                }
            }

            if (copy_to_user(&user_buffer[segments_found], &info, sizeof(MEM_SEGMENT_INFO))) {
                ret = -EFAULT;
                break;
            }
        }
        segments_found++;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    mmput(mm);
    put_task_struct(task);

    *count = segments_found;
    return ret;
}

int get_all_processes(PPROCESS_INFO user_buffer, size_t *count)
{
    struct task_struct *p;
    size_t procs_found = 0;
    size_t buffer_capacity = *count;
    int ret = 0;

    rcu_read_lock();
    for_each_process(p)
    {
        if (procs_found < buffer_capacity) {
            PROCESS_INFO info;
            struct mm_struct *mm;
            char *path_name;
            char path_buf[PROCESS_NAME_MAX];
            bool got_path = false;

            info.pid = p->pid;
            memset(info.name, 0, sizeof(info.name));

            // Use get_task_mm for safe access to mm_struct
            mm = get_task_mm(p);
            if (mm && mm->exe_file) {
                struct file *exe_file = mm->exe_file;
                if (exe_file) {
                    path_name = file_path(exe_file, path_buf, PROCESS_NAME_MAX - 1);
                    if (!IS_ERR(path_name)) {
                        strncpy(info.name, path_name, sizeof(info.name) - 1);
                        got_path = true;
                    }
                }
                mmput(mm);
            }

            // Fallback to task comm if we couldn't get the path
            if (!got_path) {
                strncpy(info.name, p->comm, sizeof(info.name) - 1);
            }

            info.name[sizeof(info.name) - 1] = '\0';

            if (copy_to_user(&user_buffer[procs_found], &info, sizeof(PROCESS_INFO))) {
                ret = -EFAULT;
                break;
            }
        }
        procs_found++;
    }
    rcu_read_unlock();

    if (ret == 0) {
        *count = procs_found;
    }

    return ret;
}
