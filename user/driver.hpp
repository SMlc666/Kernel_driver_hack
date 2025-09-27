#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h> // For getpid(), getpagesize()
#include <string.h>
#include <sys/mman.h> // For mmap
#include <vector>

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
		size_t count;    // 输入: buffer能容纳的元素数量, 输出: 实际的内存段数量
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
        OP_ANTI_PTRACE_CTL = 0x830,
	};

public:
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

    bool read_safe(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm = {this->pid, addr, buffer, size};
		return ioctl(fd, OP_READ_MEM_SAFE, &cm) == 0;
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

    pid_t get_pid(const char* name) {
        GET_PID gp;
        char buf[256];
        strncpy(buf, name, sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        gp.name = buf;
        if (ioctl(fd, OP_GET_PID, &gp) != 0) return 0;
        return gp.pid;
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

		if (gms.count > capacity) {
			capacity = gms.count;
			segments.resize(capacity);
			gms.buffer = (uintptr_t)segments.data();
			gms.count = capacity;

			if (ioctl(fd, OP_GET_MEM_SEGMENTS, &gms) != 0) {
				segments.clear();
				return false;
			}
		}

		segments.resize(gms.count);

		return true;
	}

    // --- Process Hiding ---
    bool hide_process(pid_t pid) {
        if (fd < 0) return false;
        HIDE_PROC hp = {pid, ACTION_HIDE};
        return ioctl(fd, OP_HIDE_PROC, &hp) == 0;
    }

    bool unhide_process(pid_t pid) {
        if (fd < 0) return false;
        HIDE_PROC hp = {pid, ACTION_UNHIDE};
        return ioctl(fd, OP_HIDE_PROC, &hp) == 0;
    }

    bool clear_hidden_processes() {
        if (fd < 0) return false;
        HIDE_PROC hp = {0, ACTION_CLEAR};
        return ioctl(fd, OP_HIDE_PROC, &hp) == 0;
    }

    // --- Anti-Ptrace Control ---
    bool set_anti_ptrace(bool enable) {
        if (fd < 0) return false;
        ANTI_PTRACE_CTL ctl = { enable ? ANTI_PTRACE_ENABLE : ANTI_PTRACE_DISABLE };
        return ioctl(fd, OP_ANTI_PTRACE_CTL, &ctl) == 0;
    }

    template <typename T>
	tT read(uintptr_t addr)
	{
		T buffer;
		read(addr, &buffer, sizeof(T));
		return buffer;
	}

	template <typename T>
	void write(uintptr_t addr, T buffer)
	{
		write(addr, &buffer, sizeof(T));
	}
};

static c_driver *driver = new c_driver();