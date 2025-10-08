#ifndef MMU_BREAKPOINT_H
#define MMU_BREAKPOINT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include "comm.h"
#include "inline_hook/p_lkrg_main.h"
#include "version_control.h"

#ifdef CONFIG_MMU_BREAKPOINT_MODE

static inline void khack_set_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep, pte_t pte) {
    if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
        P_SYM(p_sync_icache_dcache)(pte, addr);

    /*
     * If the existing pte is valid, check for potential race with
     * hardware updates of the pte (ptep_set_access_flags safely changes
     * valid ptes without going through an invalid entry).
     */
    if (pte_valid(*ptep) && pte_valid(pte)) {
        VM_WARN_ONCE(!pte_young(pte), "%s: racy access flag clearing: 0x%016llx -> 0x%016llx", __func__, pte_val(*ptep), pte_val(pte));
        VM_WARN_ONCE(pte_write(*ptep) && !pte_dirty(pte), "%s: racy dirty state clearing: 0x%016llx -> 0x%016llx", __func__, pte_val(*ptep), pte_val(pte));
    }
    set_pte(ptep, pte);
}

// MMU断点访问类型
#define BP_ACCESS_READ     0x01
#define BP_ACCESS_WRITE    0x02
#define BP_ACCESS_EXECUTE  0x04
#define BP_ACCESS_RW       (BP_ACCESS_READ | BP_ACCESS_WRITE)
#define BP_ACCESS_ALL      (BP_ACCESS_READ | BP_ACCESS_WRITE | BP_ACCESS_EXECUTE)

// MMU断点结构体
struct mmu_breakpoint {
    struct list_head list;        // 链表节点
    pid_t tgid;                   // 目标进程TGID (线程组ID)
    unsigned long addr;           // 断点地址
    unsigned long size;           // 监控范围
    int access_type;              // 访问类型
    pte_t original_pte;           // 原始页表项
    struct vm_area_struct *vma;   // VMA结构
    struct task_struct *task;     // 任务结构
    bool is_active;               // 是否激活
    unsigned long hit_count;      // 命中次数
};

// MMU断点信息（用于用户空间）
typedef struct _MMU_BP_INFO {
    pid_t pid;  // 实际存储的是TGID，用于兼容用户空间
    unsigned long addr;
    unsigned long size;
    int access_type;
    bool is_active;
    unsigned long hit_count;
} MMU_BP_INFO, *PMMU_BP_INFO;

// MMU断点控制结构体
typedef struct _MMU_BP_CTL {
    pid_t pid;
    unsigned long addr;
    unsigned long size;
    int access_type;
    int action;                   // 1=添加, 2=移除, 3=清空
} MMU_BP_CTL, *PMMU_BP_CTL;

// 函数声明
int mmu_breakpoint_init(void);
void mmu_breakpoint_exit(void);
int handle_mmu_breakpoint_control(PMMU_BP_CTL ctl);
int handle_mmu_breakpoint_list(pid_t tgid, PMMU_BP_INFO buffer, size_t *count);
bool is_mmu_breakpoint_active(pid_t tgid, unsigned long addr);

#include <linux/threads.h>

// For sharing with single_step.c
pte_t *virt_to_pte(struct task_struct *task, unsigned long addr);
struct mmu_breakpoint *find_breakpoint_by_pid(pid_t tgid, unsigned long addr);

#else

// If the mode is disabled, define the functions as empty inlines
static inline int mmu_breakpoint_init(void) { return 0; }
static inline void mmu_breakpoint_exit(void) { }
static inline int handle_mmu_breakpoint_control(void *ctl) { return 0; }
static inline int handle_mmu_breakpoint_list(pid_t tgid, void *buffer, size_t *count) { return 0; }
static inline bool is_mmu_breakpoint_active(pid_t tgid, unsigned long addr) { return false; }

#endif

#endif // MMU_BREAKPOINT_H
