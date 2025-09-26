#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h> // For getpid(), getpagesize()
#include <string.h>
#include <sys/mman.h> // For mmap
#include <vector>
#include "touch_shared.h"

#define DEVICE_NAME "/proc/version"

class c_driver
{
private:
	int fd;
	pid_t pid;

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

	typedef struct _HOOK_INPUT_DEVICE_DATA
	{
		char name[128];
	} HOOK_INPUT_DEVICE_DATA, *PHOOK_INPUT_DEVICE_DATA;

	typedef struct _ALLOC_MEM
	{
		pid_t pid;
		uintptr_t addr; // in: desired addr (0 for auto), out: allocated addr
		size_t size;
	} ALLOC_MEM, *PALLOC_MEM;

	// 路径最大长度
	static constexpr int SEGMENT_PATH_MAX = 256;

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
		size_t count;	 // 输入: buffer能容纳的元素数量, 输出: 实际的内存段数量
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

public:
	// HW Breakpoint-related structs, must match kernel-side
	#pragma pack(push, 1)
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
		uint64_t stack_trace[16]; // Corresponds to MAX_STACK_FRAMES
	};
	#pragma pack(pop)

	// Make the shared memory pointer public for easy access
	struct SharedTouchMemory* shared_mem = nullptr;

	c_driver()
	{
		fd = open(DEVICE_NAME, O_RDWR);
		if (fd == -1)
		{
			printf("[-] open driver failed\n");
		}
	}

	~c_driver()
	{
		if (fd > 0)
		{
			unhook_input_device();
			unmap_shared_memory();
			close(fd);
		}
	}

	bool authenticate()
	{
		if (fd < 0) return false;
		return ioctl(fd, OP_AUTHENTICATE) == 0;
	}

	bool initialize(pid_t target_pid)
	{
		if (!authenticate())
		{
			return false;
		}
		set_target_pid(target_pid);
		return true;
	}

	void set_target_pid(pid_t target_pid)
	{
		this->pid = target_pid;
	}

	// --- Memory Operations ---
	bool read(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm = {this->pid, addr, buffer, size};
		return ioctl(fd, OP_READ_MEM, &cm) == 0;
	}

	bool write(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm = {this->pid, addr, buffer, size};
		return ioctl(fd, OP_WRITE_MEM, &cm) == 0;
	}

	uintptr_t get_module_base(char *name)
	{
		MODULE_BASE mb;
		char buf[0x100];
		strcpy(buf, name);
		mb.pid = this->pid;
		mb.name = buf;
		if (ioctl(fd, OP_MODULE_BASE, &mb) != 0) return 0;
		return mb.base;
	}

	uintptr_t alloc_memory(size_t size, uintptr_t addr = 0)
	{
		if (fd < 0) return 0;
		ALLOC_MEM am = {this->pid, addr, size};
		if (ioctl(fd, OP_ALLOC_MEM, &am) != 0) return 0;
		return am.addr;
	}

	bool free_memory(uintptr_t addr, size_t size)
	{
		if (fd < 0) return false;
		ALLOC_MEM am = {this->pid, addr, size};
		return ioctl(fd, OP_FREE_MEM, &am) == 0;
	}

	bool get_memory_segments(std::vector<MEM_SEGMENT_INFO>& segments)
	{
		if (fd < 0) return false;

		size_t capacity = 128; // Start with a reasonable capacity
		segments.resize(capacity);

		GET_MEM_SEGMENTS gms;
		gms.pid = this->pid;
		gms.buffer = (uintptr_t)segments.data();
		gms.count = capacity;

		if (ioctl(fd, OP_GET_MEM_SEGMENTS, &gms) != 0) {
			segments.clear();
			return false;
		}

		// gms.count now holds the *actual* number of segments.
		if (gms.count > capacity) {
			// The buffer was too small, resize and call again.
			capacity = gms.count;
			segments.resize(capacity);
			gms.buffer = (uintptr_t)segments.data();
			gms.count = capacity;

			if (ioctl(fd, OP_GET_MEM_SEGMENTS, &gms) != 0) {
				segments.clear();
				return false;
			}
		}

		// Trim the vector to the actual size.
		segments.resize(gms.count);

		return true;
	}

	// --- Touch Control Operations ---
	bool hook_input_device(const char *name)
	{
		if (fd < 0) return false;
		HOOK_INPUT_DEVICE_DATA hidd;
		strncpy(hidd.name, name, sizeof(hidd.name) - 1);
		hidd.name[sizeof(hidd.name) - 1] = '\0';
		return ioctl(fd, OP_HOOK_INPUT_DEVICE, &hidd) == 0;
	}

	bool unhook_input_device()
	{
		if (fd < 0) return false;
		return ioctl(fd, OP_UNHOOK_INPUT_DEVICE) == 0;
	}

	// --- MMAP Management ---
	bool mmap_shared_memory() {
		if (fd < 0) return false;
		if (shared_mem) return true; // Already mapped

		long page_size = getpagesize();
		size_t map_size = (sizeof(struct SharedTouchMemory) + page_size - 1) & ~(page_size - 1);

		void* map_ptr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (map_ptr == MAP_FAILED) {
			shared_mem = nullptr;
			perror("mmap failed");
			return false;
		}
		shared_mem = (struct SharedTouchMemory*)map_ptr;
		return true;
	}

	void unmap_shared_memory() {
		if (shared_mem) {
			long page_size = getpagesize();
			size_t map_size = (sizeof(struct SharedTouchMemory) + page_size - 1) & ~(page_size - 1);
			munmap(shared_mem, map_size);
			shared_mem = nullptr;
		}
	}

	// --- Hardware Breakpoint Operations ---

	int get_num_brps() {
		if (fd < 0) return -1;
		return ioctl(fd, OP_HWBP_GET_NUM_BRPS);
	}

	int get_num_wrps() {
		if (fd < 0) return -1;
		return ioctl(fd, OP_HWBP_GET_NUM_WRPS);
	}

	uintptr_t install_hw_breakpoint(uintptr_t addr, int len, int type) {
		if (fd < 0) return 0;
		HWBP_INSTALL hwbpi = {this->pid, addr, len, type, 0};
		if (ioctl(fd, OP_HWBP_INSTALL, &hwbpi) != 0) {
			return 0;
		}
		return hwbpi.handle;
	}

	bool uninstall_hw_breakpoint(uintptr_t handle) {
		if (fd < 0) return false;
		HWBP_GENERAL hwbp_gen = {handle};
		return ioctl(fd, OP_HWBP_UNINSTALL, &hwbp_gen) == 0;
	}

	bool suspend_hw_breakpoint(uintptr_t handle) {
		if (fd < 0) return false;
		HWBP_GENERAL hwbp_gen = {handle};
		return ioctl(fd, OP_HWBP_SUSPEND, &hwbp_gen) == 0;
	}

	bool resume_hw_breakpoint(uintptr_t handle) {
		if (fd < 0) return false;
		HWBP_GENERAL hwbp_gen = {handle};
		return ioctl(fd, OP_HWBP_RESUME, &hwbp_gen) == 0;
	}

	bool get_hit_info(uintptr_t handle, uint64_t& total_hits, uint64_t& buffered_hits) {
		if (fd < 0) return false;
		HWBP_HIT_COUNT hhc = {handle, 0, 0};
		if (ioctl(fd, OP_HWBP_GET_HIT_COUNT, &hhc) != 0) {
			return false;
		}
		total_hits = hhc.total_count;
		buffered_hits = hhc.arr_count;
		return true;
	}

	std::vector<HWBP_HIT_ITEM> get_hit_details(uintptr_t handle, size_t max_count = 1024) {
		std::vector<HWBP_HIT_ITEM> hits;
		if (fd < 0) return hits;
		hits.resize(max_count);
		HWBP_HIT_DETAIL hhd = {handle, hits.data(), hits.size() * sizeof(HWBP_HIT_ITEM)};
		int items_received = ioctl(fd, OP_HWBP_GET_HIT_DETAIL, &hhd);
		if (items_received >= 0) {
			hits.resize(items_received);
		} else {
			hits.clear();
		}
		return hits;
	}

	bool set_redirect_pc(uintptr_t pc) {
		if (fd < 0) return false;
		HWBP_REDIRECT_PC rpc = {pc};
		return ioctl(fd, OP_HWBP_SET_REDIRECT_PC, &rpc) == 0;
	}
};

static c_driver *driver = new c_driver();

