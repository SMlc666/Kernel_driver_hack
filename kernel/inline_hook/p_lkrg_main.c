#include "p_lkrg_main.h"

p_lkrg_global_symbols p_global_symbols;

//cat /proc/kallsyms | grep "kallsyms_lookup_name"
//insmod arm64_hook.ko kallsyms_lookup_name_address=0xffffffc0100d4dc8
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
    static unsigned long kallsyms_lookup_name_address=0;
    module_param(kallsyms_lookup_name_address,ulong,S_IRUSR);
#endif

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
        p_print_log("Warning: kallsyms_lookup_name not available. Only direct function pointer mode will work.\n");
        return -1;
    }

#ifdef CONFIG_ARM
#ifdef CONFIG_THUMB2_KERNEL
   if (P_SYM(p_kallsyms_lookup_name))
      P_SYM(p_kallsyms_lookup_name) |= 1; /* set bit 0 in address for thumb mode */
#endif
#endif
    p_print_log("kallsyms_lookup_name:%lx\n",(unsigned long)P_SYM(p_kallsyms_lookup_name));
    return 0;
}


static int __init p_lkrg_register(void){

    int p_ret=-1;
    const struct p_functions_hooks *p_fh_it;
    int kallsyms_available = 0;

    /* Try to get kallsyms_lookup_name, but don't fail if unavailable */
    if(get_kallsyms_address() == 0){
        kallsyms_available = 1;
        p_print_log("kallsyms_lookup_name available, both name lookup and direct pointer modes supported\n");
    }else{
        p_print_log("kallsyms_lookup_name not available, only direct pointer mode supported\n");
    }

    if(inline_hook_init()!=0){
        p_print_log("init failed\n");
        return p_ret;
    }

    for (p_fh_it = p_functions_hooks_array; p_fh_it->name != NULL; p_fh_it++) {
        if (p_fh_it->install(p_fh_it->is_sys)) {
            /* Only fail if using name lookup mode without kallsyms */
            if(!kallsyms_available){
                p_print_log("Hook installation failed. Consider using direct function pointer mode.\n");
            }
            return p_ret;
        }

    }

    p_print_log("load success\n");
    return 0;
}


static void __exit p_lkrg_unregister(void){
    const struct p_functions_hooks *p_fh_it;
    
    for (p_fh_it = p_functions_hooks_array; p_fh_it->name != NULL; p_fh_it++) {
        p_fh_it->uninstall();   
    }
    p_print_log("unload success\n");
}



MODULE_LICENSE("GPL");
rg_unregister);

MODULE_LICENSE("GPL");
;
