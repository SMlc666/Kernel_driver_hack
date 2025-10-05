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

public: // Make these accessible to users of the class
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

	// New Process Spawn Control Structures
	typedef struct _SPAWN_SUSPEND_CTL
	{
	    char target_name[PROCESS_NAME_MAX]; // The name of the process to suspend
	    int enable;                      // 1 to enable, 0 to disable
	} SPAWN_SUSPEND_CTL, *PSPAWN_SUSPEND_CTL;

	typedef struct _RESUME_PROCESS_CTL
	{
	    pid_t pid; // The PID of the process to resume
	} RESUME_PROCESS_CTL, *PRESUME_PROCESS_CTL;

	// New structs for getting all processes
	static constexpr int PROCESS_NAME_MAX = 256;

	typedef struct _PROCESS_INFO
	{
		pid_t pid;
		char name[PROCESS_NAME_MAX];
	} PROCESS_INFO, *PPROCESS_INFO;

	typedef struct _GET_ALL_PROCS
	{
		uintptr_t buffer;
		size_t count;
	} GET_ALL_PROCS, *PGET_ALL_PROCS;


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
		OP_GET_MEM_SEGMENTS = 0x814,
		OP_GET_ALL_PROCS = 0x815,
        OP_ANTI_PTRACE_CTL = 0x830,

		// New Thread Ops
		OP_ENUM_THREADS = 0x840,
    	OP_THREAD_CTL = 0x841,
		OP_SINGLE_STEP_CTL = 0x850,

		// New Process Spawn Control
		OP_SET_SPAWN_SUSPEND = 0x860,
		OP_RESUME_PROCESS = 0x861,
	};

	enum THREAD_ACTION
	{
		THREAD_ACTION_SUSPEND = 1,
		THREAD_ACTION_RESUME = 2,
		THREAD_ACTION_KILL = 3,
	};

	// For single stepping
	enum STEP_ACTION
	{
		STEP_ACTION_START = 1,
		STEP_ACTION_STOP = 2,
		STEP_ACTION_STEP = 3,
		STEP_ACTION_GET_INFO = 4,
		STEP_ACTION_STEP_AND_WAIT = 5,
	};

	// User-space equivalent of ARM64 pt_regs
    typedef struct _user_pt_regs {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } user_pt_regs, *puser_pt_regs;

	typedef struct _SINGLE_STEP_CTL
    {
        pid_t tid;
        int action;
        uintptr_t regs_buffer; // Pointer to user_pt_regs
    } SINGLE_STEP_CTL, *PSINGLE_STEP_CTL;

	typedef struct _THREAD_INFO {
        pid_t tid;
        char name[PROCESS_NAME_MAX];
    } THREAD_INFO, *PTHREAD_INFO;

    typedef struct _ENUM_THREADS {
        pid_t pid;
        uintptr_t buffer;
        size_t count;
    } ENUM_THREADS, *PENUM_THREADS;

    typedef struct _THREAD_CTL {
        pid_t tid;
        int action;
    } THREAD_CTL, *PTHREAD_CTL;

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

	bool get_all_processes(std::vector<PROCESS_INFO>& processes)
	{
		if (fd < 0) return false;

		size_t capacity = 256; // Start with a reasonable capacity
		processes.resize(capacity);

		GET_ALL_PROCS gap;
		gap.buffer = (uintptr_t)processes.data();
		gap.count = capacity;

		if (ioctl(fd, OP_GET_ALL_PROCS, &gap) != 0) {
			processes.clear();
			return false;
		}

		if (gap.count > capacity) {
			capacity = gap.count;
			processes.resize(capacity);
			gap.buffer = (uintptr_t)processes.data();
			gap.count = capacity;

			if (ioctl(fd, OP_GET_ALL_PROCS, &gap) != 0) {
				processes.clear();
				return false;
			}
		}

		processes.resize(gap.count);

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

    // --- Thread Control ---
    bool suspend_thread(pid_t tid) {
        if (fd < 0) return false;
        THREAD_CTL ctl = {tid, THREAD_ACTION_SUSPEND};
        return ioctl(fd, OP_THREAD_CTL, &ctl) == 0;
    }

    bool resume_thread(pid_t tid) {
        if (fd < 0) return false;
        THREAD_CTL ctl = {tid, THREAD_ACTION_RESUME};
        return ioctl(fd, OP_THREAD_CTL, &ctl) == 0;
    }

    bool kill_thread(pid_t tid) {
        if (fd < 0) return false;
        THREAD_CTL ctl = {tid, THREAD_ACTION_KILL};
        return ioctl(fd, OP_THREAD_CTL, &ctl) == 0;
    }

    bool get_all_threads(pid_t pid, std::vector<THREAD_INFO>& threads) {
        if (fd < 0) return false;

        size_t capacity = 32; // Start with a reasonable capacity
		threads.resize(capacity);

		ENUM_THREADS et;
		et.pid = pid;
		et.buffer = (uintptr_t)threads.data();
		et.count = capacity;

		if (ioctl(fd, OP_ENUM_THREADS, &et) != 0) {
			threads.clear();
			return false;
		}

		if (et.count > capacity) {
			capacity = et.count;
			threads.resize(capacity);
			et.buffer = (uintptr_t)threads.data();
			et.count = capacity;

			if (ioctl(fd, OP_ENUM_THREADS, &et) != 0) {
				threads.clear();
				return false;
			}
		}

		threads.resize(et.count);
		return true;
    }

    // --- Single-Step Control ---
    bool start_single_step(pid_t tid) {
        if (fd < 0) return false;
        SINGLE_STEP_CTL ctl = {tid, STEP_ACTION_START, 0};
        return ioctl(fd, OP_SINGLE_STEP_CTL, &ctl) == 0;
    }

    bool stop_single_step(pid_t tid) {
        if (fd < 0) return false;
        SINGLE_STEP_CTL ctl = {tid, STEP_ACTION_STOP, 0};

        // Debug: print raw bytes being sent
        unsigned char *bytes = (unsigned char *)&ctl;
        printf("[DEBUG] stop_single_step sending %zu bytes: ", sizeof(ctl));
        for (size_t i = 0; i < sizeof(ctl); i++) {
            printf("%02x ", bytes[i]);
        }
        printf("\n");
        printf("[DEBUG] tid=%d, action=%d\n", ctl.tid, ctl.action);

        return ioctl(fd, OP_SINGLE_STEP_CTL, &ctl) == 0;
    }

    bool step(pid_t tid) {
        if (fd < 0) return false;
        SINGLE_STEP_CTL ctl = {tid, STEP_ACTION_STEP, 0};
        return ioctl(fd, OP_SINGLE_STEP_CTL, &ctl) == 0;
    }

    bool get_step_info(pid_t tid, user_pt_regs& regs) {
        if (fd < 0) return false;
        SINGLE_STEP_CTL ctl = {tid, STEP_ACTION_GET_INFO, (uintptr_t)&regs};
        return ioctl(fd, OP_SINGLE_STEP_CTL, &ctl) == 0;
    }

    bool step_and_wait(pid_t tid, user_pt_regs& regs) {
        if (fd < 0) return false;
        SINGLE_STEP_CTL ctl = {tid, STEP_ACTION_STEP_AND_WAIT, (uintptr_t)&regs};

        // Debug: print raw bytes being sent
        unsigned char *bytes = (unsigned char *)&ctl;
        printf("[DEBUG] step_and_wait sending %zu bytes: ", sizeof(ctl));
        for (size_t i = 0; i < sizeof(ctl); i++) {
            printf("%02x ", bytes[i]);
        }
        printf("\n");
        printf("[DEBUG] tid=%d, action=%d, regs_buffer=0x%lx\n", ctl.tid, ctl.action, ctl.regs_buffer);

        return ioctl(fd, OP_SINGLE_STEP_CTL, &ctl) == 0;
    }

    // --- Process Spawn Control ---
    bool set_spawn_suspend_target(const char* target_name, bool enable) {
        if (fd < 0) return false;
        SPAWN_SUSPEND_CTL ctl;
        strncpy(ctl.target_name, target_name, PROCESS_NAME_MAX - 1);
        ctl.target_name[PROCESS_NAME_MAX - 1] = '\0';
        ctl.enable = enable ? 1 : 0;
        return ioctl(fd, OP_SET_SPAWN_SUSPEND, &ctl) == 0;
    }

    bool resume_process(pid_t pid_to_resume) {
        if (fd < 0) return false;
        RESUME_PROCESS_CTL ctl = {pid_to_resume};
        return ioctl(fd, OP_RESUME_PROCESS, &ctl) == 0;
    }

    template <typename T>
	T read(uintptr_t addr)
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
