#ifndef HW_BREAKPOINT_H
#define HW_BREAKPOINT_H

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include "cvector.h"
#include "version_control.h"

// --- Data Structures ---

#pragma pack(1)
// Structure to hold detailed information about a breakpoint hit
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
};
#pragma pack()

// Structure to manage the state of a single hardware breakpoint
struct HWBP_HANDLE_INFO {
	uint64_t handle; // Use the perf_event pointer as the handle
	uint64_t task_id;
	struct perf_event *sample_hbp;
	struct perf_event_attr original_attr;
	bool is_32bit_task;
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
	struct perf_event_attr next_instruction_attr;
#endif
	size_t hit_total_count;
	cvector hit_item_arr; // cvector of HWBP_HIT_ITEM
};


// --- Public API ---

// Initialize and exit the hardware breakpoint subsystem
int khack_hw_breakpoint_init(void);
void khack_hw_breakpoint_exit(void);

// Get CPU capabilities
int hwbp_get_num_brps(void);
int hwbp_get_num_wrps(void);

// Core breakpoint management functions
int hwbp_install(pid_t pid, uintptr_t addr, int len, int type, uint64_t *handle);
int hwbp_uninstall(uint64_t handle);
int hwbp_suspend(uint64_t handle);
int hwbp_resume(uint64_t handle);

// Functions to retrieve hit data
int hwbp_get_hit_count(uint64_t handle, uint64_t *total_count, uint64_t *arr_count);
int hwbp_get_hit_detail(uint64_t handle, void __user *buffer, size_t size);

// Function to set a global redirect PC for any breakpoint hit
int hwbp_set_redirect_pc(uint64_t pc);

// For anti-ptrace module
spinlock_t *hwbp_get_mutex(void);
cvector *hwbp_get_vector(void);


#endif // HW_BREAKPOINT_H
