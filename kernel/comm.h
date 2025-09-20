#ifndef COMM_H
#define COMM_H

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
	OP_INIT_KEY = 0x800,
	OP_READ_MEM = 0x801,
	OP_WRITE_MEM = 0x802,
	OP_MODULE_BASE = 0x803,
	OP_HIDE_PROC = 0x804,
	OP_TOUCH_SET_DEVICE = 0x805,
	OP_TOUCH_SEND = 0x806,
	OP_TOUCH_DEINIT = 0x807,
	OP_GET_PID = 0x808,
	OP_READ_MEM_SAFE = 0x809,
	OP_HOOK_INPUT_DEVICE_BY_NAME = 0x80A,
};

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

#endif // COMM_H
