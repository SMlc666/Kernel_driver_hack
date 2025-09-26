#ifndef HW_BREAKPOINT_H
#define HW_BREAKPOINT_H

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include "cvector.h"

#define MAX_STACK_FRAMES 16

#pragma pack(1)
struct my_user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
	uint64_t orig_x0;
	uint64_t syscallno;
};
struct HWBP_HIT_ITEM {
	uint64_t task_id;
	uint64_t hit_addr;
	uint64_t hit_time;
	struct my_user_pt_regs regs_info;
    int stack_trace_size;
    uint64_t stack_trace[MAX_STACK_FRAMES];
};
#pragma pack()

struct HWBP_HANDLE_INFO {
	uint64_t task_id;
	struct perf_event * sample_hbp;
	struct perf_event_attr original_attr;
	bool is_32bit_task;
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
	struct perf_event_attr next_instruction_attr;
#endif
	size_t hit_total_count;
	cvector hit_item_arr;
};

int khack_hw_breakpoint_init(void);
void khack_hw_breakpoint_exit(void);

long hwbp_get_num_brps(void);
long hwbp_get_num_wrps(void);
long hwbp_install(pid_t pid, uint64_t addr, int len, int type, uint64_t* handle_out);
long hwbp_uninstall(uint64_t handle);
long hwbp_suspend(uint64_t handle);
long hwbp_resume(uint64_t handle);
long hwbp_get_hit_count(uint64_t handle, uint64_t* total_count, uint64_t* arr_count);
long hwbp_get_hit_detail(uint64_t handle, void __user *buf, size_t size);
long hwbp_set_redirect_pc(uint64_t pc);

#endif // HW_BREAKPOINT_H
