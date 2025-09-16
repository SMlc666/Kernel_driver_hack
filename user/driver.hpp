#include <sys/fcntl.h>
#include <sys/ioctl.h>

#define DEVICE_NAME "/dev/JiangNight"

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

	enum HIDE_ACTION
	{
		ACTION_HIDE = 1,
		ACTION_UNHIDE = 2,
		ACTION_CLEAR = 3,
	};

	enum OPERATIONS
	{
		OP_INIT_KEY = 0x800,
		OP_READ_MEM = 0x801,
		OP_WRITE_MEM = 0x802,
		OP_MODULE_BASE = 0x803,
		OP_HIDE_PROC = 0x804,
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
			close(fd);
	}

	void initialize(pid_t pid)
	{
		this->pid = pid;
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
};

static c_driver *driver = new c_driver();
