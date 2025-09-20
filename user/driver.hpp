#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h> // For getpid()
#include <string.h>

#define DEVICE_NAME "/proc/version"

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