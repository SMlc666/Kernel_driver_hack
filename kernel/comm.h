#ifndef COMM_H
#define COMM_H

// No longer need linux/input.h
// #include <linux/input.h> // For struct input_event

// Include necessary headers for user_pt_regs
#include <linux/types.h>
#include <asm/ptrace.h>

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
	OP_MAP_MEMORY = 0x889,
	
	// --- MMU Breakpoint Operations ---
	OP_MMU_BP_CTL = 0x890,
	OP_MMU_BP_LIST = 0x891,
	
	// --- System Call Trace Operations ---
	OP_SYSCALL_TRACE_CTL = 0x8B0,
	OP_SYSCALL_TRACE_LIST = 0x8B1,

	// --- New Touch Input Operations ---
    OP_TOUCH_HOOK_INSTALL = 0x900,
    OP_TOUCH_HOOK_UNINSTALL = 0x901,
    OP_TOUCH_SET_MODE = 0x902,
    OP_TOUCH_NOTIFY = 0x903,
    OP_TOUCH_CLEAN_STATE = 0x904,

	// --- VMA-less Memory Operations ---
    OP_VMA_LESS_ALLOC   = 0x910,
    OP_VMA_LESS_FREE    = 0x911,
    OP_VMA_LESS_PROTECT = 0x912,
    OP_VMA_LESS_QUERY   = 0x913,

	// --- Hardware Breakpoint Operations ---
	OP_HW_BREAKPOINT_CTL = 0x8A0,
	OP_HW_BREAKPOINT_GET_HITS = 0x8A1,
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


// --- New Touch Input Structures ---

// For OP_TOUCH_SET_MODE
enum TOUCH_MODE {
    TOUCH_MODE_DISABLED = 0,      // Hook installed but inactive
    TOUCH_MODE_FILTER_MODIFY = 1, // Intercept and modify real events
    TOUCH_MODE_EXCLUSIVE_INJECT = 2, // Block real events, inject from buffer
};

typedef struct _TOUCH_MODE_CTL {
    enum TOUCH_MODE mode;
} TOUCH_MODE_CTL, *PTOUCH_MODE_CTL;

// For the mmap shared buffer
#define TOUCH_BUFFER_POINTS 256 // Number of points in the ring buffer

enum TOUCH_ACTION {
    TOUCH_ACTION_DOWN,
    TOUCH_ACTION_UP,
    TOUCH_ACTION_MOVE,
};

typedef struct _TOUCH_POINT {
    enum TOUCH_ACTION action;
    unsigned int slot;
    int x;
    int y;
} TOUCH_POINT, *PTOUCH_POINT;

// The layout of the shared memory region
typedef struct _TOUCH_SHARED_BUFFER {
    volatile unsigned int head; // Written by user, read by kernel
    volatile unsigned int tail; // Written by kernel, read by user
    TOUCH_POINT points[TOUCH_BUFFER_POINTS];
} TOUCH_SHARED_BUFFER, *PTOUCH_SHARED_BUFFER;

// For OP_MAP_MEMORY
typedef struct _MAP_MEMORY_CTL {
    // Input
    pid_t source_pid;
    uintptr_t source_addr;
    size_t size;
    pid_t target_pid;
    int perms; // PROT_READ, PROT_WRITE, PROT_EXEC

    // Output
    uintptr_t mapped_addr;
} MAP_MEMORY_CTL, *PMAP_MEMORY_CTL;

// --- VMA-less Memory Operation Structures ---

// For OP_VMA_LESS_ALLOC
typedef struct _VMA_LESS_ALLOC_CTL {
    pid_t target_pid;
    size_t size;
    int perms; // PROT_READ, PROT_WRITE, PROT_EXEC

    // Output
    uintptr_t mapped_addr; // Returns the mapped address in the target process
} VMA_LESS_ALLOC_CTL, *PVMA_LESS_ALLOC_CTL;

// For OP_VMA_LESS_FREE
typedef struct _VMA_LESS_FREE_CTL {
    pid_t target_pid;
    uintptr_t addr;
    size_t size;
} VMA_LESS_FREE_CTL, *PVMA_LESS_FREE_CTL;

// For OP_VMA_LESS_PROTECT
typedef struct _VMA_LESS_PROTECT_CTL {
    pid_t target_pid;
    uintptr_t addr;
    size_t size;
    int new_perms; // New PROT_READ, PROT_WRITE, PROT_EXEC
} VMA_LESS_PROTECT_CTL, *PVMA_LESS_PROTECT_CTL;

// For OP_VMA_LESS_QUERY
typedef struct _VMA_LESS_INFO {
    uintptr_t start;
    uintptr_t end;
    int perms;
} VMA_LESS_INFO, *PVMA_LESS_INFO;

typedef struct _VMA_LESS_QUERY_CTL {
    pid_t target_pid;
    uintptr_t buffer; // Pointer to user-space VMA_LESS_INFO array
    size_t count;     // Input: buffer capacity, Output: actual count
} VMA_LESS_QUERY_CTL, *PVMA_LESS_QUERY_CTL;


// --- Hardware Breakpoint Structures ---

enum HW_BREAKPOINT_ACTION {
    HW_BP_ADD = 1,
    HW_BP_REMOVE = 2,
};

enum HW_BREAKPOINT_TYPE {
    HW_BP_TYPE_EXECUTE = 0,
    HW_BP_TYPE_WRITE   = 1,
    HW_BP_TYPE_RW      = 2,
};

typedef struct _HW_BREAKPOINT_CTL {
    pid_t           pid;
    uintptr_t       addr;
    int             action;
    int             type;
    int             len;
} HW_BREAKPOINT_CTL, *PHW_BREAKPOINT_CTL;

typedef struct _HW_BREAKPOINT_HIT_INFO {
    pid_t           pid;
    uint64_t        timestamp;
    uintptr_t       addr;
    struct user_pt_regs regs;
} HW_BREAKPOINT_HIT_INFO, *PHW_BREAKPOINT_HIT_INFO;

typedef struct _HW_BREAKPOINT_GET_HITS_CTL {
    uintptr_t       buffer;
    size_t          count;
} HW_BREAKPOINT_GET_HITS_CTL, *PHW_BREAKPOINT_GET_HITS_CTL;


#endif // COMM_H
