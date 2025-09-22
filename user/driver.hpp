#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h> // For getpid(), getpagesize()
#include <string.h>
#include <sys/mman.h> // For mmap
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
	};

public:
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

		void* map_ptr = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
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
			munmap(shared_mem, getpagesize());
			shared_mem = nullptr;
		}
	}
};

static c_driver *driver = new c_driver();

