#include "p_lkrg_main.h"
#include <linux/vmalloc.h>
#include "p_hmem.h"
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/init_task.h>
#include "../version_control.h"

void *hook_mem_buf = NULL;

p_lkrg_global_symbols p_global_symbols;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
    static unsigned long kallsyms_lookup_name_address=0;
    module_param(kallsyms_lookup_name_address,ulong,S_IRUSR);
#endif

unsigned long * get_sys_call_table(void){
	unsigned long* p_etext = NULL;
    unsigned long* p_init_begin = NULL;

#if defined(CONFIG_ARM64)
	unsigned long** syscall_table = NULL;
    unsigned long* p_sys_close = NULL;
    unsigned long* p_sys_read = NULL;
	unsigned long i;
	const char *read_names[] = {"__arm64_sys_read", "SyS_read", "sys_read", NULL};
    const char *close_names[] = {"__arm64_sys_close", "SyS_close", "sys_close", NULL};
#elif defined(CONFIG_ARM)
	unsigned long** syscall_table = NULL;
    unsigned long* p_sys_close = NULL;
    unsigned long* p_sys_read = NULL;
	unsigned long i;
	const char *read_names[] = {"sys_read", "SyS_read", NULL};
    const char *close_names[] = {"sys_close", "SyS_close", NULL};
#elif defined(CONFIG_X86_64)
	unsigned long** syscall_table = NULL;
	unsigned long* p_sys_close=NULL;
	unsigned long* p_sys_read=NULL;
	unsigned long i;
	const char *read_names[] = {"__x64_sys_read", "SyS_read", "sys_read", NULL};
    const char *close_names[] = {"__x64_sys_close", "SyS_close", "sys_close", NULL};
#elif defined(CONFIG_X86_32)
	unsigned long** syscall_table = NULL;
	unsigned long* p_sys_close=NULL;
	unsigned long* p_sys_read=NULL;
	unsigned long i;
	const char *read_names[] = {"__ia32_sys_read", "SyS_read", "sys_read", NULL};
    const char *close_names[] = {"__ia32_sys_close", "SyS_close", "sys_close", NULL};
#endif

p_etext = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("_etext");
    if(!p_etext) return NULL;

p_init_begin = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__init_begin");
	if(!p_init_begin) return NULL;

#if defined(CONFIG_ARM64) || defined(CONFIG_ARM) || defined(CONFIG_X86_64) || defined(CONFIG_X86_32)
	for (i = 0; close_names[i]; i++) {
        p_sys_close = (unsigned long*)P_SYM(p_kallsyms_lookup_name)(close_names[i]);
        if (p_sys_close) {
			PRINT_DEBUG("[get_sys_call_table] Found close symbol: %s\n", close_names[i]);
			break;
		}
    }
    if (!p_sys_close) {
		PRINT_DEBUG("[get_sys_call_table] Failed to find any close symbol.\n");
		return NULL;
	}

    for (i = 0; read_names[i]; i++) {
        p_sys_read = (unsigned long*)P_SYM(p_kallsyms_lookup_name)(read_names[i]);
        if (p_sys_read) {
			PRINT_DEBUG("[get_sys_call_table] Found read symbol: %s\n", read_names[i]);
			break;
		}
    }
    if (!p_sys_read) {
		PRINT_DEBUG("[get_sys_call_table] Failed to find any read symbol.\n");
		return NULL;
	}

	for(i = (unsigned long)p_etext;i < (unsigned long)p_init_begin;i += sizeof(void*)){
		syscall_table = (unsigned long**)i;
		if((syscall_table[__NR_close] == (unsigned long*)p_sys_close) && (syscall_table[__NR_read] == (unsigned long*)p_sys_read)){
            return (unsigned long *)syscall_table;
        }
	}
#endif

	return NULL;
}

static const struct p_functions_hooks{
    const char *name;
    int (*install)(int p_isra);
    void (*uninstall)(void);
    int is_sys;
}p_functions_hooks_array[]={
    {NULL,NULL,NULL,0}
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0))
static int p_lookup_syms_hack(void *unused, const char *name,
                              struct module *mod, unsigned long addr) {

   if (strcmp("kallsyms_lookup_name", name) == 0) {
      P_SYM(p_kallsyms_lookup_name) = (unsigned long (*)(const char*)) (addr);
      return addr;
   }

   return 0;
}
#endif


int get_kallsyms_address(void){
    int p_ret=-1;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
    if(kallsyms_lookup_name_address != 0){
        P_SYM(p_kallsyms_lookup_name)=(unsigned long (*)(const char*))kallsyms_lookup_name_address;
    }
#else
    kallsyms_on_each_symbol(p_lookup_syms_hack,NULL);
#endif
    if(!P_SYM(p_kallsyms_lookup_name)){
        PRINT_DEBUG("Warning: kallsyms_lookup_name not available. Dynamic scan failed. Only direct function pointer mode will work.\n");
        return -1;
    }

#ifdef CONFIG_ARM
#ifdef CONFIG_THUMB2_KERNEL
   if (P_SYM(p_kallsyms_lookup_name))
      P_SYM(p_kallsyms_lookup_name) |= 1; /* set bit 0 in address for thumb mode */
#endif
#endif
    PRINT_DEBUG("kallsyms_lookup_name:%lx\n",(unsigned long)P_SYM(p_kallsyms_lookup_name));
    return 0;
}


int khook_init(void){

    int p_ret=-1;
    const struct p_functions_hooks *p_fh_it;
    int kallsyms_available = 0;

    if(get_kallsyms_address() == 0){
        kallsyms_available = 1;
        PRINT_DEBUG("kallsyms_lookup_name available, both name lookup and direct pointer modes supported\n");
    }else{
        PRINT_DEBUG("kallsyms_lookup_name not available, only direct pointer mode supported\n");
    }

    if (kallsyms_available) {
        P_SYM(p_module_alloc) = (void *(*)(long))P_SYM(p_kallsyms_lookup_name)("module_alloc");
    }

    if (P_SYM(p_module_alloc)) {
        hook_mem_buf = P_SYM(p_module_alloc)(PAGE_SIZE);
        if (!hook_mem_buf) {
             PRINT_DEBUG("module_alloc hook_mem_buf failed\n");
             return -ENOMEM;
        }
        PRINT_DEBUG("Allocated hook memory with module_alloc\n");
    } else {
        PRINT_DEBUG("module_alloc not found, falling back to vmalloc\n");
        hook_mem_buf = vmalloc(PAGE_SIZE);
        if (!hook_mem_buf) {
            PRINT_DEBUG("vmalloc hook_mem_buf failed\n");
            return -ENOMEM;
        }
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
        if (set_allocate_memory_x((unsigned long)hook_mem_buf, 1) != 0) {
             PRINT_DEBUG("Failed to make vmalloc memory executable\n");
             vfree(hook_mem_buf);
             hook_mem_buf = NULL;
             return -EFAULT;
        }
#endif
    }

    hook_mem_add((uintptr_t)hook_mem_buf, PAGE_SIZE);

    for (p_fh_it = p_functions_hooks_array; p_fh_it->name != NULL; p_fh_it++) {
        if (p_fh_it->install(p_fh_it->is_sys)) {
            if(!kallsyms_available){
                PRINT_DEBUG("Hook installation failed. Consider using direct function pointer mode.\n");
            }
            return p_ret;
        }

    }

    PRINT_DEBUG("load success\n");
    return 0;
}



void khook_exit(void){
    const struct p_functions_hooks *p_fh_it;
    
    for (p_fh_it = p_functions_hooks_array; p_fh_it->name != NULL; p_fh_it++) {
        p_fh_it->uninstall();   
    }

    if (hook_mem_buf) {
        vfree(hook_mem_buf);
        hook_mem_buf = NULL;
    }
    PRINT_DEBUG("unload success\n");
}

MODULE_LICENSE("GPL");
