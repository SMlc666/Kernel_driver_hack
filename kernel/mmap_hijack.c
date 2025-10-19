#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/gfp.h>

#include "mmap_hijack.h"
#include "memory.h" // for translate_linear_address

#ifdef CONFIG_MEMORY_ACCESS_MODE

// External symbols we need
extern struct kmem_cache *vm_area_cachep;
extern int khack_insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma);

int handle_map_memory(PMAP_MEMORY_CTL ctl)
{
    struct task_struct *source_task = NULL, *target_task = NULL;
    struct mm_struct *source_mm = NULL, *target_mm = NULL;
    struct vm_area_struct *source_vma = NULL, *target_vma = NULL;
    unsigned long target_addr = 0;
    int ret = 0;
    unsigned long size_aligned = PAGE_ALIGN(ctl->size);
    long num_pages = size_aligned / PAGE_SIZE;
    struct page **pages = NULL;
    long i;

    // 1. Get task and memory manager structs
    source_task = get_pid_task(find_get_pid(ctl->source_pid), PIDTYPE_PID);
    target_task = get_pid_task(find_get_pid(ctl->target_pid), PIDTYPE_PID);
    if (!source_task || !target_task) {
        ret = -ESRCH;
        goto out_put_tasks;
    }

    source_mm = get_task_mm(source_task);
    target_mm = get_task_mm(target_task);
    if (!source_mm || !target_mm) {
        ret = -EINVAL;
        goto out_put_mm;
    }

    // 2. Validate source address range
    down_read(&source_mm->mmap_sem);
    source_vma = find_vma(source_mm, ctl->source_addr);
    if (!source_vma || (ctl->source_addr + ctl->size) > source_vma->vm_end) {
        up_read(&source_mm->mmap_sem);
        ret = -EFAULT; // Invalid address range or crosses VMA boundaries
        goto out_put_mm;
    }
    up_read(&source_mm->mmap_sem);

    // Allocate memory for page pointers
    pages = vmalloc(num_pages * sizeof(struct page *));
    if (!pages) {
        ret = -ENOMEM;
        goto out_put_mm;
    }

    // 3. Pin the source pages in memory
    down_read(&source_mm->mmap_sem);
    ret = get_user_pages(ctl->source_addr, num_pages, FOLL_WRITE, pages, NULL);
    up_read(&source_mm->mmap_sem);

    if (ret < num_pages) {
        // Failed to get all pages, release the ones we got
        if (ret > 0) {
            for (i = 0; i < ret; i++) {
                put_page(pages[i]);
            }
        }
        ret = -EFAULT;
        goto out_free_pages_array;
    }
    // At this point, ret == num_pages

    // 4. Allocate and prepare a new VMA for the target process
    down_write(&target_mm->mmap_sem);

    target_vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
    if (!target_vma) {
        ret = -ENOMEM;
        goto out_unlock_target_and_release_pages;
    }

    target_addr = get_unmapped_area(NULL, 0, size_aligned, 0, 0);
    if (IS_ERR_VALUE(target_addr)) {
        ret = target_addr;
        kmem_cache_free(vm_area_cachep, target_vma);
        goto out_unlock_target_and_release_pages;
    }

    // Initialize the new VMA
    target_vma->vm_mm = target_mm;
    target_vma->vm_start = target_addr;
    target_vma->vm_end = target_addr + size_aligned;
    
    target_vma->vm_flags = VM_SHARED;
    if ((ctl->perms & PROT_READ) && (source_vma->vm_flags & VM_READ)) target_vma->vm_flags |= VM_READ;
    if ((ctl->perms & PROT_WRITE) && (source_vma->vm_flags & VM_WRITE)) target_vma->vm_flags |= VM_WRITE;
    if ((ctl->perms & PROT_EXEC) && (source_vma->vm_flags & VM_EXEC)) target_vma->vm_flags |= VM_EXEC;
    
    target_vma->vm_page_prot = vm_get_page_prot(target_vma->vm_flags);

    // 5. Map pages one by one using the pinned pages
    for (i = 0; i < num_pages; i++) {
        unsigned long current_target_va = target_addr + (i * PAGE_SIZE);
        unsigned long pfn = page_to_pfn(pages[i]);

        ret = remap_pfn_range(target_vma, current_target_va, pfn, PAGE_SIZE, target_vma->vm_page_prot);
        if (ret) {
            kmem_cache_free(vm_area_cachep, target_vma);
            goto out_unlock_target_and_release_pages;
        }
    }

    // 6. Insert the new VMA into the target's address space
    if (khack_insert_vm_struct(target_mm, target_vma)) {
        kmem_cache_free(vm_area_cachep, target_vma);
        ret = -ENOMEM;
        goto out_unlock_target_and_release_pages;
    }

    // 7. Success, set the mapped address for the user
    ctl->mapped_addr = target_addr;
    ret = 0;

out_unlock_target_and_release_pages:
    up_write(&target_mm->mmap_sem);

    // Release the pages acquired by get_user_pages
    for (i = 0; i < num_pages; i++) {
        put_page(pages[i]);
    }

out_free_pages_array:
    vfree(pages);
out_put_mm:
    if (source_mm) mmput(source_mm);
    if (target_mm) mmput(target_mm);
out_put_tasks:
    if (source_task) put_task_struct(source_task);
    if (target_task) put_task_struct(target_task);

    return ret;
}
#endif
