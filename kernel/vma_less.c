#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "vma_less.h"
#include "memory.h" // for translate_linear_address

#ifdef CONFIG_MEMORY_ACCESS_MODE

// Data structure to track VMA-less mappings
struct vma_less_mapping {
    struct list_head list;
    pid_t pid;
    uintptr_t start;
    size_t size;
    int perms;
    struct page **pages;
    long num_pages;
};

// Global list and lock for tracking mappings
static LIST_HEAD(vma_less_mappings);
static DEFINE_SPINLOCK(vma_less_lock);

// Forward declarations for static functions
static struct vma_less_mapping* find_mapping(pid_t pid, uintptr_t addr);
static int map_pages_to_proc(struct mm_struct *mm, uintptr_t addr, struct page **pages, long num_pages, int perms);
static void unmap_pages_from_proc(struct mm_struct *mm, uintptr_t addr, size_t size);
static uintptr_t find_free_gap(struct mm_struct *mm, size_t size);

int vma_less_init(void) {
    PRINT_DEBUG("[+] vma_less: Initialized.\n");
    return 0;
}

void vma_less_exit(void) {
    // Cleanup any remaining mappings on module unload
    struct vma_less_mapping *mapping, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&vma_less_lock, flags);
    list_for_each_entry_safe(mapping, tmp, &vma_less_mappings, list) {
        // This is a simplified cleanup. A robust version would need the mm_struct.
        // For now, we just free the tracking data and physical pages.
        long i;
        for (i = 0; i < mapping->num_pages; i++) {
            __free_page(mapping->pages[i]);
        }
        vfree(mapping->pages);
        list_del(&mapping->list);
        kfree(mapping);
    }
    spin_unlock_irqrestore(&vma_less_lock, flags);
    PRINT_DEBUG("[+] vma_less: Exited and cleaned up mappings.\n");
}

int handle_vma_less_alloc(PVMA_LESS_ALLOC_CTL ctl)
{
    struct task_struct *task;
    struct mm_struct *mm;
    uintptr_t addr = 0;
    struct page **pages = NULL;
    long num_pages;
    struct vma_less_mapping *mapping = NULL;
    int ret = 0;
    long i;

    if (ctl->size == 0) return -EINVAL;
    num_pages = PAGE_ALIGN(ctl->size) / PAGE_SIZE;

    // 1. Get task and mm
    task = get_pid_task(find_get_pid(ctl->target_pid), PIDTYPE_PID);
    if (!task) return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }

    // 2. Find free address space
    addr = find_free_gap(mm, PAGE_ALIGN(ctl->size));
    if (!addr) {
        ret = -ENOMEM;
        goto out_put_mm;
    }

    // 3. Allocate physical pages
    pages = vmalloc(num_pages * sizeof(struct page *));
    if (!pages) {
        ret = -ENOMEM;
        goto out_put_mm;
    }
    for (i = 0; i < num_pages; i++) {
        pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!pages[i]) {
            for (i--; i >= 0; i--) __free_page(pages[i]);
            vfree(pages);
            ret = -ENOMEM;
            goto out_put_mm;
        }
    }

    // 4. Map pages into process's page table
    ret = map_pages_to_proc(mm, addr, pages, num_pages, ctl->perms);
    if (ret) {
        for (i = 0; i < num_pages; i++) __free_page(pages[i]);
        vfree(pages);
        goto out_put_mm;
    }

    // 5. Create and add tracking structure
    mapping = kmalloc(sizeof(struct vma_less_mapping), GFP_KERNEL);
    if (!mapping) {
        unmap_pages_from_proc(mm, addr, PAGE_ALIGN(ctl->size));
        for (i = 0; i < num_pages; i++) __free_page(pages[i]);
        vfree(pages);
        ret = -ENOMEM;
        goto out_put_mm;
    }
    mapping->pid = ctl->target_pid;
    mapping->start = addr;
    mapping->size = PAGE_ALIGN(ctl->size);
    mapping->perms = ctl->perms;
    mapping->pages = pages;
    mapping->num_pages = num_pages;

    spin_lock(&vma_less_lock);
    list_add(&mapping->list, &vma_less_mappings);
    spin_unlock(&vma_less_lock);

    ctl->mapped_addr = addr;

out_put_mm:
    mmput(mm);
    put_task_struct(task);
    return ret;
}

int handle_vma_less_free(PVMA_LESS_FREE_CTL ctl)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vma_less_mapping *mapping;
    int ret = 0;
    long i;

    // 1. Find the mapping in our internal list
    mapping = find_mapping(ctl->target_pid, ctl->addr);
    if (!mapping || mapping->size != PAGE_ALIGN(ctl->size)) {
        return -EINVAL;
    }

    // 2. Get task and mm
    task = get_pid_task(find_get_pid(ctl->target_pid), PIDTYPE_PID);
    if (!task) return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }

    // 3. Unmap pages from the process's page table
    unmap_pages_from_proc(mm, mapping->start, mapping->size);

    // 4. Free the physical pages
    for (i = 0; i < mapping->num_pages; i++) {
        __free_page(mapping->pages[i]);
    }
    vfree(mapping->pages);

    // 5. Remove from tracking list and free the mapping structure
    spin_lock(&vma_less_lock);
    list_del(&mapping->list);
    spin_unlock(&vma_less_lock);
    kfree(mapping);

    mmput(mm);
    put_task_struct(task);
    PRINT_DEBUG("[+] vma_less: Freed mapping for PID %d at 0x%lx\n", ctl->target_pid, ctl->addr);
    return ret;
}

int handle_vma_less_protect(PVMA_LESS_PROTECT_CTL ctl)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vma_less_mapping *mapping;
    int ret = 0;
    long i;
    pgprot_t new_prot = PAGE_KERNEL;

    mapping = find_mapping(ctl->target_pid, ctl->addr);
    if (!mapping || mapping->size != PAGE_ALIGN(ctl->size)) {
        return -EINVAL;
    }

    task = get_pid_task(find_get_pid(ctl->target_pid), PIDTYPE_PID);
    if (!task) return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }

    if (ctl->new_perms & PROT_EXEC) new_prot = pgprot_exec(new_prot);
    if (!(ctl->new_perms & PROT_WRITE)) new_prot = pgprot_wrprotect(new_prot);

    down_write(&mm->mmap_sem);
    for (i = 0; i < mapping->num_pages; i++) {
        uintptr_t current_addr = mapping->start + (i * PAGE_SIZE);
        pte_t *ptep = virt_to_pte(task, current_addr); // Assuming virt_to_pte is available
        if (ptep) {
            set_pte_at(mm, current_addr, ptep, pte_modify(ptep_get(ptep), new_prot));
        }
    }
    flush_tlb_range(mm, mapping->start, mapping->start + mapping->size);
    up_write(&mm->mmap_sem);

    mapping->perms = ctl->new_perms;

    mmput(mm);
    put_task_struct(task);
    PRINT_DEBUG("[+] vma_less: Changed protection for PID %d at 0x%lx\n", ctl->target_pid, ctl->addr);
    return ret;
}

int handle_vma_less_query(PVMA_LESS_QUERY_CTL ctl)
{
    struct vma_less_mapping *mapping;
    size_t found = 0;
    size_t capacity = ctl->count;
    int ret = 0;
    unsigned long flags;

    spin_lock_irqsave(&vma_less_lock, flags);
    list_for_each_entry(mapping, &vma_less_mappings, list) {
        if (mapping->pid == ctl->target_pid) {
            if (found < capacity) {
                VMA_LESS_INFO info;
                info.start = mapping->start;
                info.end = mapping->start + mapping->size;
                info.perms = mapping->perms;
                if (copy_to_user(&((PVMA_LESS_INFO)ctl->buffer)[found], &info, sizeof(VMA_LESS_INFO))) {
                    ret = -EFAULT;
                    break;
                }
            }
            found++;
        }
    }
    spin_unlock_irqrestore(&vma_less_lock, flags);

    if (ret == 0) {
        ctl->count = found;
    }

    return ret;
}


// --- Static Helper Implementations ---

static struct vma_less_mapping* find_mapping(pid_t pid, uintptr_t addr)
{
    struct vma_less_mapping *mapping;
    unsigned long flags;

    spin_lock_irqsave(&vma_less_lock, flags);
    list_for_each_entry(mapping, &vma_less_mappings, list) {
        if (mapping->pid == pid && mapping->start == addr) {
            spin_unlock_irqrestore(&vma_less_lock, flags);
            return mapping;
        }
    }
    spin_unlock_irqrestore(&vma_less_lock, flags);
    return NULL;
}

static uintptr_t find_free_gap(struct mm_struct *mm, size_t size)
{
    // A simplified version of get_unmapped_area
    // This is not robust against all edge cases but is a starting point.
    return vm_mmap(NULL, 0, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
}

static int map_pages_to_proc(struct mm_struct *mm, uintptr_t addr, struct page **pages, long num_pages, int perms)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    pgprot_t prot = PAGE_KERNEL;
    int ret = 0;
    long i;

    if (perms & PROT_EXEC) prot = pgprot_exec(prot);
    if (!(perms & PROT_WRITE)) prot = pgprot_wrprotect(prot);

    down_write(&mm->mmap_sem);

    for (i = 0; i < num_pages; i++) {
        uintptr_t current_addr = addr + (i * PAGE_SIZE);

        pgd = pgd_offset(mm, current_addr);
        p4d = p4d_alloc(mm, pgd, current_addr);
        if (!p4d) { ret = -ENOMEM; break; }

        pud = pud_alloc(mm, p4d, current_addr);
        if (!pud) { ret = -ENOMEM; break; }

        pmd = pmd_alloc(mm, pud, current_addr);
        if (!pmd) { ret = -ENOMEM; break; }

        ptep = pte_alloc_map(mm, pmd, current_addr);
        if (!ptep) { ret = -ENOMEM; break; }

        set_pte_at(mm, current_addr, ptep, mk_pte(pages[i], prot));
        pte_unmap(ptep);
    }

    if (ret) {
        // Rollback on failure
        unmap_pages_from_proc(mm, addr, (i * PAGE_SIZE));
    } else {
        flush_tlb_range(mm, addr, addr + (num_pages * PAGE_SIZE));
    }

    up_write(&mm->mmap_sem);
    return ret;
}

static void unmap_pages_from_proc(struct mm_struct *mm, uintptr_t addr, size_t size)
{
    uintptr_t end = addr + size;
    uintptr_t current_addr;

    down_write(&mm->mmap_sem);

    for (current_addr = addr; current_addr < end; current_addr += PAGE_SIZE) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep;

        pgd = pgd_offset(mm, current_addr);
        if (pgd_none(*pgd)) continue;

        p4d = p4d_offset(pgd, current_addr);
        if (p4d_none(*p4d)) continue;

        pud = pud_offset(p4d, current_addr);
        if (pud_none(*pud)) continue;

        pmd = pmd_offset(pud, current_addr);
        if (pmd_none(*pmd)) continue;

        ptep = pte_offset_map(mm, pmd, current_addr);
        if (ptep) {
            pte_clear(mm, current_addr, ptep);
            pte_unmap(ptep);
        }
    }

    flush_tlb_range(mm, addr, end);
    up_write(&mm->mmap_sem);
}
#endif // CONFIG_MEMORY_ACCESS_MODE
