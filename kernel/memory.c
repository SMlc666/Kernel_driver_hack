#include <linux/kallsyms.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/list.h>

#include "memory.h"

// Define function pointer types for the functions we need to look up
typedef struct vm_struct *(*get_vm_area_caller_t)(unsigned long, unsigned long, void *);
typedef int (*ioremap_page_range_t)(unsigned long, unsigned long, phys_addr_t, pgprot_t);

// Global variables to hold the resolved function addresses
static get_vm_area_caller_t get_vm_area_caller_ptr;
static ioremap_page_range_t ioremap_page_range_ptr;

// Function to resolve symbols using kallsyms_lookup_name.
static int resolve_manual_ioremap_symbols(void)
{
	if (get_vm_area_caller_ptr && ioremap_page_range_ptr)
		return 0;

	get_vm_area_caller_ptr = (get_vm_area_caller_t)kallsyms_lookup_name("get_vm_area_caller");
	if (!get_vm_area_caller_ptr) {
		printk(KERN_ERR "[KHACK] Failed to resolve get_vm_area_caller\n");
		return -ENOENT;
	}

	ioremap_page_range_ptr = (ioremap_page_range_t)kallsyms_lookup_name("ioremap_page_range");
	if (!ioremap_page_range_ptr) {
		printk(KERN_ERR "[KHACK] Failed to resolve ioremap_page_range\n");
		return -ENOENT;
	}
    
	return 0;
}


// Based on the kernel source provided by the user, using dynamically resolved symbols.
static void __iomem *my_ioremap_ram_nocache(phys_addr_t phys_addr, size_t size)
{
	unsigned long last_addr;
	unsigned long offset = phys_addr & ~PAGE_MASK;
	int err;
	unsigned long addr;
	struct vm_struct *area;
    void *caller = __builtin_return_address(0);

    if (resolve_manual_ioremap_symbols() != 0) {
        printk(KERN_ERR "[KHACK] Cannot perform manual ioremap, symbols not found.\n");
        return NULL;
    }

	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(size + offset);

	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr || (last_addr & ~PHYS_MASK))
		return NULL;

	printk(KERN_INFO "[KHACK_DEBUG] Calling get_vm_area_caller_ptr for size %zu\n", size);
	area = get_vm_area_caller_ptr(size, VM_IOREMAP, caller);
	if (!area) {
		printk(KERN_ERR "[KHACK_DEBUG] get_vm_area_caller_ptr FAILED and returned NULL!\n");
		return NULL;
	}
	addr = (unsigned long)area->addr;
	area->phys_addr = phys_addr;
	printk(KERN_INFO "[KHACK_DEBUG] get_vm_area_caller_ptr OK. addr = 0x%lx\n", addr);

	printk(KERN_INFO "[KHACK_DEBUG] Calling ioremap_page_range_ptr for pa=0x%llx, va=0x%lx\n", (unsigned long long)phys_addr, addr);
	err = ioremap_page_range_ptr(addr, addr + size, phys_addr, pgprot_noncached(PAGE_KERNEL));
	if (err) {
		printk(KERN_ERR "[KHACK_DEBUG] ioremap_page_range_ptr FAILED with error code %d\n", err);
		vunmap((void *)addr);
		return NULL;
	}

	printk(KERN_INFO "[KHACK_DEBUG] ioremap_page_range_ptr OK.\n");
	return (void __iomem *)(offset + addr);
}


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
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
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
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#endif


static inline int my_valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}


bool read_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!my_valid_phys_addr_range(pa, size))
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
	if (!my_valid_phys_addr_range(pa, size))
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
	bool result = true;
	size_t bytes_remaining = size;
	uintptr_t current_addr = addr;
	char __user *current_buffer = (char __user *)buffer;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) return false;

	mm = get_task_mm(task);
	if (!mm) return false;

	while (bytes_remaining > 0)
	{
		size_t offset_in_page = current_addr & (PAGE_SIZE - 1);
		size_t bytes_to_boundary = PAGE_SIZE - offset_in_page;
		size_t chunk_size = bytes_remaining < bytes_to_boundary ? bytes_remaining : bytes_to_boundary;

		phys_addr_t pa = translate_linear_address(mm, current_addr);
		if (!pa)
		{
			if (find_vma(mm, current_addr))
			{
				if (clear_user(current_buffer, chunk_size) != 0)
				{
					result = false;
					break;
				}
			}
			else
			{
				result = false;
				break;
			}
		}
		else
		{
			if (!read_physical_address(pa, current_buffer, chunk_size))
			{
				result = false;
				break;
			}
		}

		bytes_remaining -= chunk_size;
		current_addr += chunk_size;
		current_buffer += chunk_size;
	}

	mmput(mm);
	return result;
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
	bool result = true;
	size_t bytes_remaining = size;
	uintptr_t current_addr = addr;
	char __user *current_buffer = (char __user *)buffer;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) return false;

	mm = get_task_mm(task);
	if (!mm) return false;

	while (bytes_remaining > 0)
	{
		size_t offset_in_page = current_addr & (PAGE_SIZE - 1);
		size_t bytes_to_boundary = PAGE_SIZE - offset_in_page;
		size_t chunk_size = bytes_remaining < bytes_to_boundary ? bytes_remaining : bytes_to_boundary;

		phys_addr_t pa = translate_linear_address(mm, current_addr);
		if (!pa)
		{
			result = false;
			break;
		}

		if (!write_physical_address(pa, current_buffer, chunk_size))
		{
			result = false;
			break;
		}

		bytes_remaining -= chunk_size;
		current_addr += chunk_size;
		current_buffer += chunk_size;
	}

	mmput(mm);
	return result;
}

#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES 64
#endif

static inline void manual_flush_dcache_area(void *addr, size_t size)
{
    unsigned long i;
    for (i = (unsigned long)addr; i < (unsigned long)addr + size; i += L1_CACHE_BYTES) {
        // Data Cache Clean and Invalidate by VA to Point of Coherency
        asm volatile("dc civac, %0" : : "r"(i) : "memory");
    }
    asm volatile("dsb ish" : : : "memory"); // Ensure completion
}

bool read_physical_address_safe(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!my_valid_phys_addr_range(pa, size))
	{
		return false;
	}
	mapped = my_ioremap_ram_nocache(pa, size);
	if (!mapped)
	{
		return false;
	}
	if (copy_to_user(buffer, mapped, size))
	{
		iounmap(mapped);
		return false;
	}

    // Per user's suggestion, flush the cache for the area we just read
    // to fight the hardware prefetcher.
    manual_flush_dcache_area(mapped, size);

	iounmap(mapped);
	return true;
}

bool read_process_memory_safe(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	bool result = true;
	size_t bytes_remaining = size;
	uintptr_t current_addr = addr;
	char __user *current_buffer = (char __user *)buffer;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) return false;

	mm = get_task_mm(task);
	if (!mm) return false;

	while (bytes_remaining > 0)
	{
		size_t offset_in_page = current_addr & (PAGE_SIZE - 1);
		size_t bytes_to_boundary = PAGE_SIZE - offset_in_page;
		size_t chunk_size = bytes_remaining < bytes_to_boundary ? bytes_remaining : bytes_to_boundary;

		phys_addr_t pa = translate_linear_address(mm, current_addr);
		if (!pa)
		{
			if (find_vma(mm, current_addr))
			{
				if (clear_user(current_buffer, chunk_size) != 0)
				{
					result = false;
					break;
				}
			}
			else
			{
				result = false;
				break;
			}
		}
		else
		{
			if (!read_physical_address_safe(pa, current_buffer, chunk_size))
			{
				result = false;
				break;
			}
		}

		bytes_remaining -= chunk_size;
		current_addr += chunk_size;
		current_buffer += chunk_size;
	}

	mmput(mm);
	return result;
}

uintptr_t alloc_process_memory(pid_t pid, uintptr_t addr, size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	if (!task)
		return 0;

	mm = get_task_mm(task);
	if (!mm)
	{
		put_task_struct(task);
		return 0;
	}

	size = PAGE_ALIGN(size);
	if (size == 0)
	{
		mmput(mm);
		put_task_struct(task);
		return 0;
	}

	mmap_write_lock(mm);

	if (addr == 0)
	{
		unsigned long gap_start = mm->mmap_base;
		struct vm_area_struct *iter_vma;
		for (iter_vma = mm->mmap; iter_vma; iter_vma = iter_vma->vm_next)
		{
			if (iter_vma->vm_start > gap_start)
			{
				if ((iter_vma->vm_start - gap_start) >= size)
				{
					addr = gap_start;
					break;
				}
			}
			gap_start = iter_vma->vm_end;
		}
		if (addr == 0)
		{
			if (TASK_SIZE > gap_start && TASK_SIZE - gap_start >= size)
			{
				addr = gap_start;
			}
		}
	}
	else
	{
		addr = PAGE_ALIGN(addr);
		if (find_vma_intersection(mm, addr, addr + size))
		{
			addr = 0;
		}
	}

	if (addr == 0)
	{
		mmap_write_unlock(mm);
		mmput(mm);
		put_task_struct(task);
		return 0;
	}

	vma = vm_area_alloc(mm);
	if (!vma)
	{
		mmap_write_unlock(mm);
		mmput(mm);
		put_task_struct(task);
		return 0;
	}

	vma->vm_start = addr;
	vma->vm_end = addr + size;
	vma->vm_flags = VM_READ | VM_WRITE | VM_EXEC | VM_ANON | VM_PRIVATE;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_pgoff = 0;
	vma->vm_file = NULL;
	vma->vm_private_data = NULL;

	if (insert_vm_struct(mm, vma))
	{
		vm_area_free(vma);
		mmap_write_unlock(mm);
		mmput(mm);
		put_task_struct(task);
		return 0;
	}

	mmap_write_unlock(mm);
	mmput(mm);
	put_task_struct(task);

	return addr;
}

int free_process_memory(pid_t pid, uintptr_t addr, size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct list_head uf;
	int result;

	task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	if (!task) return -ESRCH;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&uf);
	
	mmap_write_lock(mm);
	result = do_munmap(mm, addr, size, &uf);
	mmap_write_unlock(mm);

	mmput(mm);
	put_task_struct(task);

	return result;
}
