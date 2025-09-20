#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h> // For getpid()
#include <string.h>
#include <linux/input.h> // For struct input_event

#define DEVICE_NAME "/proc/version"

#define MAX_TOUCH_POINTS 10

// This struct is defined in the kernel's comm.h
// We redefine it here for user-space use.
#define MAX_EVENTS_PER_READ 64
typedef struct _EVENT_PACKAGE {
    struct input_event events[MAX_EVENTS_PER_READ];
    unsigned int count;
} EVENT_PACKAGE, *PEVENT_PACKAGE;

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


typedef struct _TOUCH_INIT_DATA
{
    int max_x;
    int max_y;
} TOUCH_INIT_DATA, *PTOUCH_INIT_DATA;


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
		OP_HOOK_INPUT_DEVICE_BY_NAME = 0x80A, // Legacy
		// New commands for pure kernel-space event hijacking
		OP_HOOK_INPUT_DEVICE = 0x810,
		OP_UNHOOK_INPUT_DEVICE = 0x811,
		OP_READ_INPUT_EVENTS = 0x812,
		OP_INJECT_INPUT_EVENT = 0x813,
		OP_HEARTBEAT = 0x814,
		OP_INJECT_INPUT_PACKAGE = 0x815,
		OP_SET_TOUCH_MODE = 0x816,
	};

	public:
	enum touch_mode {
		MODE_PASS_THROUGH = 0,
		MODE_INTERCEPT = 1
	};

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
			unhook_input_device(); // Ensure unhook on destruction
			touch_deinit();
			close(fd);
		}
	}

	// Must be called first to establish connection with the driver
	bool authenticate()
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_AUTHENTICATE) != 0)
		{
			printf("[-] Authentication failed\n");
			return false;
		}
        // The driver now knows our PID.
		return true;
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

	// Set the PID of the process you want to operate on
	void set_target_pid(pid_t target_pid)
	{
		this->pid = target_pid;
	}

	bool read(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_READ_MEM, &cm) != 0)
		{
			return false;
		}
		return true;
	}

	bool read_safe(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_READ_MEM_SAFE, &cm) != 0)
		{
			return false;
		}
		return true;
	}

	bool write(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_WRITE_MEM, &cm) != 0)
		{
			return false;
		}
		return true;
	}

	template <typename T>
	T read(uintptr_t addr)
	{
		T res;
		if (this->read(addr, &res, sizeof(T)))
			return res;
		return {};
	}

	template <typename T>
	T read_safe(uintptr_t addr)
	{
		T res;
		if (this->read_safe(addr, &res, sizeof(T)))
			return res;
		return {};
	}

	template <typename T>
	bool write(uintptr_t addr, T value)
	{
		return this->write(addr, &value, sizeof(T));
	}

	uintptr_t get_module_base(char *name)
	{
		MODULE_BASE mb;
		char buf[0x100];
		strcpy(buf, name);
		mb.pid = this->pid;
		mb.name = buf;

		if (ioctl(fd, OP_MODULE_BASE, &mb) != 0)
		{
			return 0;
		}
		return mb.base;
	}

	pid_t get_pid(const char *name)
	{
		GET_PID gp;
		char buf[0x100];
		strcpy(buf, name);
		gp.name = buf;
		gp.pid = 0;

		if (ioctl(fd, OP_GET_PID, &gp) != 0)
		{
			return 0;
		}
		return gp.pid;
	}

	bool hide_process(pid_t target_pid)
	{
		HIDE_PROC hp;
		hp.pid = target_pid;
		hp.action = ACTION_HIDE;

		if (ioctl(fd, OP_HIDE_PROC, &hp) != 0)
		{
			return false;
		}
		return true;
	}

	bool unhide_process(pid_t target_pid)
	{
		HIDE_PROC hp;
		hp.pid = target_pid;
		hp.action = ACTION_UNHIDE;

		if (ioctl(fd, OP_HIDE_PROC, &hp) != 0)
		{
			return false;
		}
		return true;
	}

	bool clear_hidden_processes()
	{
		HIDE_PROC hp;
		hp.pid = 0;
		hp.action = ACTION_CLEAR;

		if (ioctl(fd, OP_HIDE_PROC, &hp) != 0)
		{
			return false;
		}
		return true;
	}

	// --- New Hijacking API ---

	bool hook_input_device(const char *name)
	{
		if (fd < 0) return false;
		HOOK_INPUT_DEVICE_DATA hidd;
		strncpy(hidd.name, name, sizeof(hidd.name) - 1);
		hidd.name[sizeof(hidd.name) - 1] = '\0';

		if (ioctl(fd, OP_HOOK_INPUT_DEVICE, &hidd) != 0)
		{
			printf("[-] hook_input_device failed for name: %s\n", name);
			return false;
		}
		printf("[+] Kernel driver is now hijacking device: %s\n", name);
		return true;
	}

	bool unhook_input_device()
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_UNHOOK_INPUT_DEVICE) != 0)
		{
			return false;
		}
		printf("[+] Unhooked device.\n");
		return true;
	}

	bool read_input_events(PEVENT_PACKAGE pkg)
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_READ_INPUT_EVENTS, pkg) != 0)
		{
			// This can fail if the hook is terminated, which is not an error
			return false;
		}
		return true;
	}

	bool inject_input_event(struct input_event *event)
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_INJECT_INPUT_EVENT, event) != 0)
		{
			return false;
		}
		return true;
	}

	bool inject_input_package(PEVENT_PACKAGE pkg)
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_INJECT_INPUT_PACKAGE, pkg) != 0)
		{
			return false;
		}
		return true;
	}

	bool send_heartbeat()
	{
		if (fd < 0) return false;
		return ioctl(fd, OP_HEARTBEAT) == 0;
	}

	bool set_touch_mode(touch_mode mode)
	{
		if (fd < 0) return false;
		int val = mode;
		if (ioctl(fd, OP_SET_TOUCH_MODE, &val) != 0)
		{
			return false;
		}
		return true;
	}

	// --- Legacy Touch API ---

	bool touch_set_device(const char *path)
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_TOUCH_SET_DEVICE, path) != 0)
		{
			printf("[-] touch_set_device failed for path: %s\n", path);
			return false;
		}
		printf("[+] Touch device successfully set to %s\n", path);
		return true;
	}

	bool hook_input_device_by_name(const char *name)
	{
		if (fd < 0) return false;
		HOOK_INPUT_DEVICE_DATA hidd;
		strncpy(hidd.name, name, sizeof(hidd.name) - 1);
		hidd.name[sizeof(hidd.name) - 1] = '\0';

		if (ioctl(fd, OP_HOOK_INPUT_DEVICE_BY_NAME, &hidd) != 0)
		{
			printf("[-] hook_input_device_by_name failed for name: %s\n", name);
			return false;
		}
		printf("[+] Kernel driver is now targeting device name: %s\n", name);
		return true;
	}

	bool touch_send(PTOUCH_DATA data)
	{
		if (fd < 0) return false;
		if (ioctl(fd, OP_TOUCH_SEND, data) != 0)
		{
			return false;
		}
		return true;
	}

	void touch_deinit()
	{
		if (fd < 0) return;
		ioctl(fd, OP_TOUCH_DEINIT);
	}
};

static c_driver *driver = new c_driver();
