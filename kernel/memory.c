#include "memory.h"
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#endif

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}
#endif

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}
	mapped = ioremap_cache(pa, size);
	if (!mapped)
	{
		return false;
	}
	if (copy_to_user(buffer, mapped, size))
	{
		iounmap(mapped);
		return false;
	}
	iounmap(mapped);
	return true;
}

bool write_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}
	mapped = ioremap_cache(pa, size);
	if (!mapped)
	{
		return false;
	}
	if (copy_from_user(mapped, buffer, size))
	{
		iounmap(mapped);
		return false;
	}
	iounmap(mapped);
	return true;
}

bool read_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	size_t bytes_read = 0;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		put_pid(pid_struct);
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		put_task_struct(task);
		put_pid(pid_struct);
		return false;
	}

	while (bytes_read < size)
	{
		size_t bytes_to_read;
		size_t offset_in_page = (addr + bytes_read) & (PAGE_SIZE - 1);
		
		bytes_to_read = PAGE_SIZE - offset_in_page;
		if (bytes_to_read > size - bytes_read)
		{
			bytes_to_read = size - bytes_read;
		}

		pa = translate_linear_address(mm, addr + bytes_read);
		if (pa == 0)
		{
			mmput(mm);
			put_task_struct(task);
			put_pid(pid_struct);
			return false;
		}

		if (!read_physical_address(pa, (char *)buffer + bytes_read, bytes_to_read))
		{
			mmput(mm);
			put_task_struct(task);
			put_pid(pid_struct);
			return false;
		}

		bytes_read += bytes_to_read;
	}

	mmput(mm);
	put_task_struct(task);
	put_pid(pid_struct);
	return true;
}

bool write_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	size_t bytes_written = 0;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		put_pid(pid_struct);
		return false;
	}

	mm = get_task_mm(task);
	if (!mm)
	{
		put_task_struct(task);
		put_pid(pid_struct);
		return false;
	}

	while (bytes_written < size)
	{
		size_t bytes_to_write;
		size_t offset_in_page = (addr + bytes_written) & (PAGE_SIZE - 1);


		bytes_to_write = PAGE_SIZE - offset_in_page;
		if (bytes_to_write > size - bytes_written)
		{
			bytes_to_write = size - bytes_written;
		}
		pa = translate_linear_address(mm, addr + bytes_written);
		if (pa == 0)
		{
			mmput(mm);
			put_task_struct(task);
			put_pid(pid_struct);
			return false;
		}

		if (!write_physical_address(pa, (char __user *)buffer + bytes_written, bytes_to_write))
		{
			mmput(mm);
			put_task_struct(task);
			put_pid(pid_struct);
			return false;
		}

		bytes_written += bytes_to_write;
	}

	mmput(mm);
	put_task_struct(task);
	put_pid(pid_struct);
	return true;
}