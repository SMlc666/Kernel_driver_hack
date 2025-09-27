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

typedef struct _GET_PID
{
	char *name;
	pid_t pid;
} GET_PID, *PGET_PID;

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
	OP_GET_PID = 0x808,
	OP_READ_MEM_SAFE = 0x809,

	OP_ALLOC_MEM = 0x812,
	OP_FREE_MEM = 0x813,
	OP_GET_MEM_SEGMENTS = 0x814,
	OP_GET_ALL_PROCS = 0x815,

    // Anti-ptrace control
    OP_ANTI_PTRACE_CTL = 0x830,

    // --- New Thread Control Operations ---
    OP_ENUM_THREADS = 0x840,
    OP_THREAD_CTL = 0x841,

    // --- New Hardware Breakpoint Operations ---
    OP_SET_HW_BREAKPOINT    = 0x850,
    OP_CLEAR_HW_BREAKPOINT  = 0x851,
};

// For controlling a specific thread
enum THREAD_ACTION
{
    THREAD_ACTION_SUSPEND = 1,
    THREAD_ACTION_RESUME = 2,
    THREAD_ACTION_KILL = 3,
};

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


// Struct for getting all processes
typedef struct _PROCESS_INFO
{
    pid_t pid;
    char name[16]; // TASK_COMM_LEN
} PROCESS_INFO, *PPROCESS_INFO;

typedef struct _GET_ALL_PROCS
{
    uintptr_t buffer; // user-space buffer
    size_t count;     // in: buffer capacity, out: actual process count
} GET_ALL_PROCS, *PGET_ALL_PROCS;

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

typedef struct _ALLOC_MEM
{
	pid_t pid;
	uintptr_t addr; // in: desired addr (0 for auto), out: allocated addr
	size_t size;
} ALLOC_MEM, *PALLOC_MEM;

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


// --- New Hardware Breakpoint Structures ---

// Breakpoint type
enum HW_BREAKPOINT_TYPE
{
    HW_BREAKPOINT_EXECUTE = 0, // 指令执行断点
    HW_BREAKPOINT_WRITE   = 1, // 内存写断点
    HW_BREAKPOINT_READWRITE = 3, // 内存读写断点
};

// For setting/clearing a hardware breakpoint
typedef struct _HW_BREAKPOINT_CTL
{
    pid_t tid;                  // Target Thread ID (currently unused in phase 1, but for future use)
    int reg_index;              // 要使用的硬件断点寄存器索引 (e.g., 0-3)
    uintptr_t address;          // 断点地址
    int type;                   // 断点类型 (see HW_BREAKPOINT_TYPE)
    int len;                    // 监视的长度 (e.g., 1, 2, 4, 8 bytes)
    int action;                 // Internal use for enable/disable flag
} HW_BREAKPOINT_CTL, *PHW_BREAKPOINT_CTL;


#endif // COMM_H