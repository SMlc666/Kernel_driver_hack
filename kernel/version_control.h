#ifndef VERSION_CONTROL_H
#define VERSION_CONTROL_H

#include <linux/printk.h>

// Set to 1 to enable debug prints, 0 to disable them.
#define DEBUG_PRINT 1

#if DEBUG_PRINT
    #define PRINT_DEBUG(fmt, ...) printk(KERN_INFO "[KHACK_DEBUG] " fmt, ##__VA_ARGS__)
#else
    #define PRINT_DEBUG(fmt, ...) do {} while(0)
#endif

// Module configuration macros - Define these to enable/disable specific features
// To disable a module, comment out its #define line with //

// Anti-ptrace detection module (hides hardware breakpoints from ptrace)
#define CONFIG_ANTI_PTRACE_DETECTION_MODE

// Process hiding module (hide from /proc and kill operations)
#define CONFIG_HIDE_PROC_MODE

// Memory access module (read/write process memory - base functionality)
#define CONFIG_MEMORY_ACCESS_MODE

// Thread control module (suspend/resume/kill threads)
#define CONFIG_THREAD_CONTROL_MODE

// Single step debugging module
#define CONFIG_SINGLE_STEP_MODE

// Process spawn suspend module (suspend processes on spawn)
#define CONFIG_SPAWN_SUSPEND_MODE

// MMU breakpoint module (memory access breakpoints)
#define CONFIG_MMU_BREAKPOINT_MODE

// System call trace module
//#define CONFIG_SYSCALL_TRACE_MODE

// Touch input control module
#define CONFIG_TOUCH_INPUT_MODE

// Register access module (read/write CPU registers)
#define CONFIG_REGISTER_ACCESS_MODE

// Kallsyms lookup support (required for some modules)
#define CONFIG_KALLSYMS_LOOKUP_NAME

// Modify hit next mode (if needed)
#define CONFIG_MODIFY_HIT_NEXT_MODE

#endif // VERSION_CONTROL_H
