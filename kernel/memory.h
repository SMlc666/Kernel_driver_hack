#include <linux/kernel.h>
#include <linux/sched.h>
#include "version_control.h"

#ifdef CONFIG_MEMORY_ACCESS_MODE

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size);

bool write_physical_address(phys_addr_t pa, void *buffer, size_t size);

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

bool read_physical_address_safe(phys_addr_t pa, void *buffer, size_t size);

bool read_process_memory_safe(pid_t pid, uintptr_t addr, void *buffer, size_t size);

#else

// If the mode is disabled, define the functions as empty inlines that return safe defaults
static inline phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va) { return 0; }

static inline bool read_physical_address(phys_addr_t pa, void *buffer, size_t size) { return false; }

static inline bool write_physical_address(phys_addr_t pa, void *buffer, size_t size) { return false; }

static inline bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size) { return false; }

static inline bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size) { return false; }

static inline bool read_physical_address_safe(phys_addr_t pa, void *buffer, size_t size) { return false; }

static inline bool read_process_memory_safe(pid_t pid, uintptr_t addr, void *buffer, size_t size) { return false; }

#endif // CONFIG_MEMORY_ACCESS_MODE
