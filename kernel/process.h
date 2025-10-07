#include <linux/kernel.h>
#include "comm.h" // 为了 MEM_SEGMENT_INFO

uintptr_t get_module_base(pid_t pid, char *name);

int get_process_memory_segments(pid_t pid, PMEM_SEGMENT_INFO user_buffer, size_t *count);

pid_t get_process_pid(const char *name);
