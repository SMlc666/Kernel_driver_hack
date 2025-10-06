#ifndef COMM_H
#define COMM_H

// No longer need linux/input.h
// #include <linux/input.h> // For struct input_event

typedef struct _COPY_MEMORY
{
	pid_t pid;
	uintptr_t addr;
	void *buffer;
	size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE
{
	pid_t pid;
	char *name;
	uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

typedef struct _HIDE_PROC
{
	pid_t pid;
	int action;
} HIDE_PROC, *PHIDE_PROC;



enum HIDE_ACTION
{
	ACTION_HIDE = 1,
	ACTION_UNHIDE = 2,
	ACTION_CLEAR = 3,
};

enum OPERATIONS
{
	OP_AUTHENTICATE = 0x7FF,
	OP_READ_MEM = 0x801,
	OP_WRITE_MEM = 0x802,
	OP_MODULE_BASE = 0x803,
	OP_HIDE_PROC = 0x804,

	OP_READ_MEM_SAFE = 0x809,

	OP_GET_MEM_SEGMENTS = 0x814,
	OP_GET_ALL_PROCS = 0x815,

    // Anti-ptrace control
    OP_ANTI_PTRACE_CTL = 0x830,

    // --- New Thread Control Operations ---
    OP_ENUM_THREADS = 0x840,
    OP_THREAD_CTL = 0x841,

    // --- New Single-Step Operations ---
    OP_SINGLE_STEP_CTL = 0x850,

    // --- New Process Spawn Control ---
    OP_SET_SPAWN_SUSPEND = 0x860,
    OP_RESUME_PROCESS = 0x861,

	// --- New Register Access Operations ---
	OP_REG_ACCESS = 0x870,
	
	// --- Module Unload Operation ---
	OP_UNLOAD_MODULE = 0x888,
	
	// --- MMU Breakpoint Operations ---
	OP_MMU_BP_CTL = 0x890,
	OP_MMU_BP_LIST = 0x891,
	
	// --- System Call Trace Operations ---
	OP_SYSCALL_TRACE_CTL = 0x8B0,
	OP_SYSCALL_TRACE_LIST = 0x8B1,
};

// For controlling a specific thread
enum THREAD_ACTION
{
    THREAD_ACTION_SUSPEND = 1,
    THREAD_ACTION_RESUME = 2,
    THREAD_ACTION_KILL = 3,
};

// --- New Single-Step-related Structures ---
enum STEP_ACTION
{
    STEP_ACTION_START = 1,
    STEP_ACTION_STOP = 2,
    STEP_ACTION_STEP = 3,
    STEP_ACTION_GET_INFO = 4,
    STEP_ACTION_STEP_AND_WAIT = 5,
};

typedef struct _SINGLE_STEP_CTL
{
    pid_t tid;
    int action;
    uintptr_t regs_buffer;
} SINGLE_STEP_CTL, *PSINGLE_STEP_CTL;

// --- New Thread-related Structures ---

// For enumerating threads in a process
typedef struct _THREAD_INFO
{
    pid_t tid;          // Thread ID
    char name[16];      // TASK_COMM_LEN
} THREAD_INFO, *PTHREAD_INFO;

typedef struct _ENUM_THREADS
{
    pid_t pid;          // Input: Process ID (TGID)
    uintptr_t buffer;   // User-space buffer for THREAD_INFO array
    size_t count;       // in: buffer capacity, out: actual thread count
} ENUM_THREADS, *PENUM_THREADS;

typedef struct _THREAD_CTL
{
    pid_t tid;          // Input: Target Thread ID
    int action;         // Input: Action to perform (see THREAD_ACTION)
} THREAD_CTL, *PTHREAD_CTL;




// 路径最大长度
#define SEGMENT_PATH_MAX 256

// 用于描述单个内存段信息的结构体
typedef struct _MEM_SEGMENT_INFO
{
    uintptr_t start;
    uintptr_t end;
    unsigned long flags;
    char path[SEGMENT_PATH_MAX];
} MEM_SEGMENT_INFO, *PMEM_SEGMENT_INFO;

// 用于 ioctl 的参数结构体
typedef struct _GET_MEM_SEGMENTS
{
    pid_t pid;
    uintptr_t buffer; // 指向用户空间的 MEM_SEGMENT_INFO 数组
    size_t count;     // 输入: buffer能容纳的元素数量, 输出: 实际的内存段数量
} GET_MEM_SEGMENTS, *PGET_MEM_SEGMENTS;

// New struct for anti-ptrace control
enum ANTI_PTRACE_ACTION
{
    ANTI_PTRACE_DISABLE = 0,
    ANTI_PTRACE_ENABLE = 1,
};

typedef struct _ANTI_PTRACE_CTL
{
    int action; // see ANTI_PTRACE_ACTION
} ANTI_PTRACE_CTL, *PANTI_PTRACE_CTL;


// --- New Process Spawn Control Structures ---

#define PROCESS_NAME_MAX 256

// For setting a target process to suspend on spawn
typedef struct _SPAWN_SUSPEND_CTL
{
    char target_name[PROCESS_NAME_MAX]; // The name of the process to suspend
    int enable;                      // 1 to enable, 0 to disable
} SPAWN_SUSPEND_CTL, *PSPAWN_SUSPEND_CTL;

// For resuming a suspended process
typedef struct _RESUME_PROCESS_CTL
{
    pid_t pid; // The PID of the process to resume
} RESUME_PROCESS_CTL, *PRESUME_PROCESS_CTL;


#endif // COMM_H
