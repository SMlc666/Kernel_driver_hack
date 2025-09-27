#include <linux/kernel.h>
#include "comm.h" // 为了 MEM_SEGMENT_INFO

uintptr_t get_module_base(pid_t pid, char *name);
pid_t get_pid_by_name(const char *pname);
int get_process_memory_segments(pid_t pid, PMEM_SEGMENT_INFO user_buffer, size_t *count);
int get_all_processes(PPROCESS_INFO user_buffer, size_t *count);
