#ifndef API_PROXY_H
#define API_PROXY_H

#include "inline_hook/p_lkrg_main.h" // For P_SYM
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include "version_control.h"

// Function pointers
static struct perf_event* (*real_register_user_hw_breakpoint)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
static void (*real_unregister_hw_breakpoint)(struct perf_event *bp);
static int (*real_modify_user_hw_breakpoint)(struct perf_event *bp, struct perf_event_attr *attr);

// Init function to resolve symbols
static inline int hwbp_resolve_api_symbols(void) {
    if (P_SYM(p_kallsyms_lookup_name) == NULL) {
        PRINT_DEBUG("[-] kallsyms_lookup_name not available.\n");
        return -1;
    }

    real_register_user_hw_breakpoint = (void *)P_SYM(p_kallsyms_lookup_name)("register_user_hw_breakpoint");
    if (!real_register_user_hw_breakpoint) {
        PRINT_DEBUG("[-] Failed to resolve register_user_hw_breakpoint\n");
        return -1;
    }

    real_unregister_hw_breakpoint = (void *)P_SYM(p_kallsyms_lookup_name)("unregister_hw_breakpoint");
    if (!real_unregister_hw_breakpoint) {
        PRINT_DEBUG("[-] Failed to resolve unregister_hw_breakpoint\n");
        return -1;
    }

    #ifdef CONFIG_MODIFY_HIT_NEXT_MODE
    real_modify_user_hw_breakpoint = (void *)P_SYM(p_kallsyms_lookup_name)("modify_user_hw_breakpoint");
    if (!real_modify_user_hw_breakpoint) {
        PRINT_DEBUG("[-] Failed to resolve modify_user_hw_breakpoint\n");
        return -1;
    }
    #endif
    
    PRINT_DEBUG("[+] HWBP API symbols resolved successfully.\n");
    return 0;
}

// Proxies
static inline struct perf_event* x_register_user_hw_breakpoint(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk) {
	return real_register_user_hw_breakpoint(attr, triggered, context, tsk);
}

static inline void x_unregister_hw_breakpoint(struct perf_event *bp) {
	real_unregister_hw_breakpoint(bp);
}

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
static inline int x_modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr) {
	return real_modify_user_hw_breakpoint(bp, attr);
}
#endif

#endif // API_PROXY_H