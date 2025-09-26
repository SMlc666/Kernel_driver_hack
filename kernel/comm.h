#ifndef COMM_H
#define COMM_H

#include <linux/input.h> // For struct input_event

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

	// New control commands for touch
	OP_HOOK_INPUT_DEVICE = 0x810,
	OP_UNHOOK_INPUT_DEVICE = 0x811,
	OP_ALLOC_MEM = 0x812,
	OP_FREE_MEM = 0x813,
	OP_GET_MEM_SEGMENTS = 0x814,

	// New HWBP ops
	OP_HWBP_GET_NUM_BRPS = 0x820,
	OP_HWBP_GET_NUM_WRPS = 0x821,
	OP_HWBP_INSTALL = 0x822,
	OP_HWBP_UNINSTALL = 0x823,
	OP_HWBP_GET_HIT_COUNT = 0x824,
	OP_HWBP_GET_HIT_DETAIL = 0x825,
	OP_HWBP_SET_REDIRECT_PC = 0x826,
	OP_HWBP_SUSPEND = 0x827,
	OP_HWBP_RESUME = 0x828,
};

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

typedef struct _HWBP_INSTALL {
	pid_t pid;
	uintptr_t addr;
	int len;
	int type;
	uintptr_t handle; // out
} HWBP_INSTALL, *PHWBP_INSTALL;

typedef struct _HWBP_GENERAL {
	uintptr_t handle;
} HWBP_GENERAL, *PHWBP_GENERAL;

typedef struct _HWBP_HIT_COUNT {
	uintptr_t handle;
	uint64_t total_count;
	uint64_t arr_count;
} HWBP_HIT_COUNT, *PHWBP_HIT_COUNT;

typedef struct _HWBP_HIT_DETAIL {
	uintptr_t handle;
	void* buffer;
	size_t size;
} HWBP_HIT_DETAIL, *PHWBP_HIT_DETAIL;

typedef struct _HWBP_REDIRECT_PC {
	uint64_t pc;
} HWBP_REDIRECT_PC, *PHWBP_REDIRECT_PC;

// New struct for event batching
#define MAX_EVENTS_PER_READ 64
typedef struct _EVENT_PACKAGE {
    struct input_event events[MAX_EVENTS_PER_READ];
    unsigned int count;
} EVENT_PACKAGE, *PEVENT_PACKAGE;

// Used for OP_HOOK_INPUT_DEVICE_BY_NAME
typedef struct _HOOK_INPUT_DEVICE_DATA
{
	char name[128];
} HOOK_INPUT_DEVICE_DATA, *PHOOK_INPUT_DEVICE_DATA;

#define MAX_TOUCH_POINTS 10

typedef struct _TOUCH_POINT
{
    int id;
    int x;
    int y;
    int size1;
    int size2;
    int size3;
} TOUCH_POINT, *PTOUCH_POINT;

typedef struct _TOUCH_DATA
{
    int point_count;
    bool is_down; // overall touch state
    TOUCH_POINT points[MAX_TOUCH_POINTS];
} TOUCH_DATA, *PTOUCH_DATA;

typedef struct _ALLOC_MEM
{
	pid_t pid;
	uintptr_t addr; // in: desired addr (0 for auto), out: allocated addr
	size_t size;
} ALLOC_MEM, *PALLOC_MEM;

#endif // COMM_H
