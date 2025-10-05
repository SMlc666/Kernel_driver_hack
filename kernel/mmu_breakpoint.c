#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/smp.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <asm/traps.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>

#include "mmu_breakpoint.h"
#include "single_step.h"
#include "inline_hook/p_lkrg_main.h"
#include "inline_hook/p_hook.h"
#include "inline_hook/utils/p_memory.h"
#include "version_control.h"

// 全局断点列表
static LIST_HEAD(mmu_breakpoints);
static DEFINE_SPINLOCK(mmu_bp_lock);
static DEFINE_MUTEX(mmu_bp_mutex);

// 函数指针
static void (*user_enable_single_step_)(struct task_struct *);
static void (*user_disable_single_step_)(struct task_struct *);

// 钩子函数声明
static void hooked_handle_pte_fault(hook_fargs1_t *fargs, void *udata);

// 当前正在处理的断点 (non-static)
struct mmu_breakpoint *current_bp = NULL;

// 刷新所有CPU的TLB和缓存
static void flush_all(void) {
    flush_tlb_all();
}

// 虚拟地址到页表项的转换 (non-static)
pte_t *virt_to_pte(struct task_struct *task, unsigned long addr) {
    struct mm_struct *mm = task->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    if (!mm)
        return NULL;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep)
        return NULL;

    return ptep;
}

// 查找断点
static struct mmu_breakpoint *find_breakpoint(pid_t pid, unsigned long addr) {
    struct mmu_breakpoint *bp;
    
    spin_lock(&mmu_bp_lock);
    list_for_each_entry(bp, &mmu_breakpoints, list) {
        if (bp->pid == pid && addr >= bp->addr && addr < bp->addr + bp->size) {
            spin_unlock(&mmu_bp_lock);
            return bp;
        }
    }
    spin_unlock(&mmu_bp_lock);
    return NULL;
}

// 设置断点（移除页面存在位）
static int set_breakpoint(struct mmu_breakpoint *bp) {
    pte_t *ptep;
    
    ptep = virt_to_pte(bp->task, bp->addr);
    if (!ptep) {
        PRINT_DEBUG("[-] mmu_bp: Failed to get PTE for addr 0x%lx\n", bp->addr);
        return -EFAULT;
    }
    
    // 保存原始页表项
    bp->vma = find_vma(bp->task->mm, bp->addr);
    if (!bp->vma) {
        PRINT_DEBUG("[-] mmu_bp: Failed to find VMA for addr 0x%lx\n", bp->addr);
        return -EFAULT;
    }
    do {
        struct mm_struct *mm = bp->vma->vm_mm;
        pte_t pte;
        pte = ptep_get_and_clear(mm, bp->addr, ptep);
        flush_tlb_page(bp->vma, bp->addr);
        bp->original_pte = pte;
    } while (0);
    
    bp->is_active = true;
    PRINT_DEBUG("[+] mmu_bp: Breakpoint set for PID %d at 0x%lx\n", bp->pid, bp->addr);
    return 0;
}

// 清除断点（恢复页面存在位）
static int clear_breakpoint(struct mmu_breakpoint *bp) {
    pte_t *ptep;
    
    if (!bp->is_active)
        return 0;
    
    ptep = virt_to_pte(bp->task, bp->addr);
    if (!ptep) {
        PRINT_DEBUG("[-] mmu_bp: Failed to get PTE for addr 0x%lx\n", bp->addr);
        return -EFAULT;
    }
    
    // 恢复原始页表项
    set_pte(ptep, bp->original_pte);
    flush_all();
    
    bp->is_active = false;
    PRINT_DEBUG("[+] mmu_bp: Breakpoint cleared for PID %d at 0x%lx\n", bp->pid, bp->addr);
    return 0;
}

// 钩子函数：处理页面错误
static void hooked_handle_pte_fault(hook_fargs1_t *fargs, void *udata) {
    struct vm_fault *vmf = (struct vm_fault *)fargs->arg0;
    struct mmu_breakpoint *bp;
    unsigned long addr = vmf->address;
    
    // 检查是否是我们的断点
    bp = find_breakpoint(current->pid, addr);
    if (!bp) {
        return; // Let original function run
    }
    
    // 检查访问类型是否匹配
    if (vmf->flags & FAULT_FLAG_INSTRUCTION) {
        if (!(bp->access_type & BP_ACCESS_EXECUTE)) {
            return; // Let original function run
        }
        PRINT_DEBUG("[+] mmu_bp: EXECUTE fault at 0x%lx, IP: 0x%lx\n", addr, task_pt_regs(current)->pc);
    } else if (vmf->flags & FAULT_FLAG_WRITE) {
        if (!(bp->access_type & BP_ACCESS_WRITE)) {
            return; // Let original function run
        }
        PRINT_DEBUG("[+] mmu_bp: WRITE fault at 0x%lx\n", addr);
    } else {
        if (!(bp->access_type & BP_ACCESS_READ)) {
            return; // Let original function run
        }
        PRINT_DEBUG("[+] mmu_bp: READ fault at 0x%lx\n", addr);
    }
    
    // It's our breakpoint, handle it and skip the original function
    fargs->skip_origin = 1;
    fargs->ret = 0; // Original function returns 0 on success for this path

    // 恢复页面权限
    vmf->pte = pte_offset_map(vmf->pmd, vmf->address);
    set_pte(vmf->pte, bp->original_pte);
    flush_all();
    
    // 增加命中计数
    bp->hit_count++;
    current_bp = bp;
    
    // 启用单步调试
    if (user_enable_single_step_) {
        user_enable_single_step_(current);
    }
}

// 添加断点
static int add_breakpoint(pid_t pid, unsigned long addr, unsigned long size, int access_type) {
    struct mmu_breakpoint *bp;
    struct task_struct *task;
    int ret;
    
    // 检查是否已存在
    if (find_breakpoint(pid, addr)) {
        PRINT_DEBUG("[-] mmu_bp: Breakpoint already exists for PID %d at 0x%lx\n", pid, addr);
        return -EEXIST;
    }
    
    // 获取任务结构
    task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        PRINT_DEBUG("[-] mmu_bp: Task not found for PID %d\n", pid);
        return -ESRCH;
    }
    
    // 创建断点结构
    bp = kmalloc(sizeof(struct mmu_breakpoint), GFP_KERNEL);
    if (!bp) {
        put_task_struct(task);
        return -ENOMEM;
    }
    
    // 初始化断点
    bp->pid = pid;
    bp->addr = addr;
    bp->size = size;
    bp->access_type = access_type;
    bp->task = task;
    bp->is_active = false;
    bp->hit_count = 0;
    
    // 设置断点
    ret = set_breakpoint(bp);
    if (ret) {
        kfree(bp);
        put_task_struct(task);
        return ret;
    }
    
    // 添加到列表
    mutex_lock(&mmu_bp_mutex);
    list_add(&bp->list, &mmu_breakpoints);
    mutex_unlock(&mmu_bp_mutex);
    
    PRINT_DEBUG("[+] mmu_bp: Added breakpoint for PID %d at 0x%lx (size: %lu, type: 0x%x)\n", 
               pid, addr, size, access_type);
    return 0;
}

// 移除断点
static int remove_breakpoint(pid_t pid, unsigned long addr) {
    struct mmu_breakpoint *bp, *tmp;
    bool found = false;
    
    mutex_lock(&mmu_bp_mutex);
    list_for_each_entry_safe(bp, tmp, &mmu_breakpoints, list) {
        if (bp->pid == pid && addr >= bp->addr && addr < bp->addr + bp->size) {
            clear_breakpoint(bp);
            list_del(&bp->list);
            put_task_struct(bp->task);
            kfree(bp);
            found = true;
            break;
        }
    }
    mutex_unlock(&mmu_bp_mutex);
    
    if (!found) {
        PRINT_DEBUG("[-] mmu_bp: Breakpoint not found for PID %d at 0x%lx\n", pid, addr);
        return -ENOENT;
    }
    
    PRINT_DEBUG("[+] mmu_bp: Removed breakpoint for PID %d at 0x%lx\n", pid, addr);
    return 0;
}

// 清空所有断点
static int clear_all_breakpoints(void) {
    struct mmu_breakpoint *bp, *tmp;
    int count = 0;
    
    mutex_lock(&mmu_bp_mutex);
    list_for_each_entry_safe(bp, tmp, &mmu_breakpoints, list) {
        clear_breakpoint(bp);
        list_del(&bp->list);
        put_task_struct(bp->task);
        kfree(bp);
        count++;
    }
    mutex_unlock(&mmu_bp_mutex);
    
    PRINT_DEBUG("[+] mmu_bp: Cleared %d breakpoints\n", count);
    return 0;
}

// 公共接口实现
int handle_mmu_breakpoint_control(PMMU_BP_CTL ctl) {
    int ret = 0;
    
    PRINT_DEBUG("[+] mmu_bp: Control request - PID: %d, Addr: 0x%lx, Action: %d\n", 
               ctl->pid, ctl->addr, ctl->action);
    
    switch (ctl->action) {
        case 1: // 添加
            ret = add_breakpoint(ctl->pid, ctl->addr, ctl->size, ctl->access_type);
            break;
        case 2: // 移除
            ret = remove_breakpoint(ctl->pid, ctl->addr);
            break;
        case 3: // 清空
            ret = clear_all_breakpoints();
            break;
        default:
            ret = -EINVAL;
            break;
    }
    
    return ret;
}

int handle_mmu_breakpoint_list(pid_t pid, PMMU_BP_INFO buffer, size_t *count) {
    struct mmu_breakpoint *bp;
    size_t found = 0;
    size_t capacity = *count;
    int ret = 0;
    
    mutex_lock(&mmu_bp_mutex);
    list_for_each_entry(bp, &mmu_breakpoints, list) {
        if (pid == 0 || bp->pid == pid) {
            if (found < capacity) {
                MMU_BP_INFO info;
                info.pid = bp->pid;
                info.addr = bp->addr;
                info.size = bp->size;
                info.access_type = bp->access_type;
                info.is_active = bp->is_active;
                info.hit_count = bp->hit_count;
                
                if (copy_to_user(&buffer[found], &info, sizeof(MMU_BP_INFO))) {
                    ret = -EFAULT;
                    break;
                }
            }
            found++;
        }
    }
    mutex_unlock(&mmu_bp_mutex);
    
    *count = found;
    return ret;
}

bool is_mmu_breakpoint_active(pid_t pid, unsigned long addr) {
    struct mmu_breakpoint *bp = find_breakpoint(pid, addr);
    return bp && bp->is_active;
}

// 初始化函数
int mmu_breakpoint_init(void) {
    void *handle_pte_fault_addr;
    
    PRINT_DEBUG("[+] mmu_bp: Initializing MMU breakpoint system\n");
    
    // 解析符号
    user_enable_single_step_ = (void (*)(struct task_struct *))kallsyms_lookup_name("user_enable_single_step");
    user_disable_single_step_ = (void (*)(struct task_struct *))kallsyms_lookup_name("user_disable_single_step");
    
    if (!user_enable_single_step_ || !user_disable_single_step_) {
        PRINT_DEBUG("[-] mmu_bp: Failed to resolve required single-step symbols\n");
        return -ENOENT;
    }

    handle_pte_fault_addr = (void *)kallsyms_lookup_name("handle_pte_fault");
    if (!handle_pte_fault_addr) {
        PRINT_DEBUG("[-] mmu_bp: Failed to find handle_pte_fault\n");
        return -ENOENT;
    }
    
    // 设置钩子
    if (hook_wrap(handle_pte_fault_addr, 1, hooked_handle_pte_fault, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] mmu_bp: Failed to wrap handle_pte_fault()\n");
        return -1;
    }
    
    PRINT_DEBUG("[+] mmu_bp: MMU breakpoint system initialized successfully\n");
    return 0;
}

// 退出函数
void mmu_breakpoint_exit(void) {
    void *handle_pte_fault_addr;

    PRINT_DEBUG("[+] mmu_bp: Shutting down MMU breakpoint system\n");
    
    // 清空所有断点
    clear_all_breakpoints();
    
    // 移除钩子
    handle_pte_fault_addr = (void *)kallsyms_lookup_name("handle_pte_fault");
    if (handle_pte_fault_addr) {
        hook_unwrap(handle_pte_fault_addr, hooked_handle_pte_fault, NULL);
    }
    
    PRINT_DEBUG("[+] mmu_bp: MMU breakpoint system shutdown complete\n");
}