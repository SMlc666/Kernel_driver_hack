#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM64)
unsigned char hook_code[]={
    0xE1,0x03,0xBE,0xA9,
    0x40,0x00,0x00,0x58,
    0x00,0x00,0x1F,0xD6,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};

unsigned char hook_ret_code[]={
    0x49,0x00,0x00,0x58,
    0x20,0x01,0x1F,0xD6,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};

#define KHOOK_STUB_ARM64_ALL "arm64_stub64_all.inc"
#define KHOOK_STUB_ARM64 "arm64_stub64.inc"

static const char arm64_stub_all_template[] = {
#include KHOOK_STUB_ARM64_ALL
};

static const char arm64_stub_template[] = {
#include KHOOK_STUB_ARM64
};



static inline void arm64_stub_fixup(hook_stub *stub, const void *entry,const void *ret){
	stub->entry_handle=(unsigned long)entry;
    stub->ret_handle=(unsigned long)ret;
    stub->use_count_addr=(unsigned long)&stub->use_count;
}

int inline_hook_install(void *arg)
{
    struct p_hook_struct * p_current_hook_struct=NULL;
	hook_stub * stub=NULL;
    int remain=0;
    int p_ret=-1;

    p_current_hook_struct=(struct p_hook_struct*)arg;
    stub=p_current_hook_struct->stub;

    if(p_current_hook_struct->ret_fn==NULL){
		memcpy(stub,arm64_stub_template,sizeof(arm64_stub_template));
	}else{
		memcpy(stub,arm64_stub_all_template,sizeof(arm64_stub_all_template));
	}

    stub->nbytes=ARM64_HOOK_SIZE;
    arm64_stub_fixup(stub,p_current_hook_struct->entry_fn,p_current_hook_struct->ret_fn);
    *(unsigned long*)&hook_code[12]=(unsigned long)stub->hook;
    *(unsigned long*)&hook_ret_code[8]=(unsigned long)p_current_hook_struct->addr+stub->nbytes;

    memcpy(stub->orig, p_current_hook_struct->addr, stub->nbytes);
    memcpy(stub->orig+stub->nbytes,hook_ret_code,sizeof(hook_ret_code));
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    p_ret = remap_write_range(p_current_hook_struct->addr, hook_code, stub->nbytes, true);
#else
    remain=PAGE_SIZE-(((unsigned long)p_current_hook_struct->addr)%PAGE_SIZE);
    //Double Page
    if(remain<stub->nbytes){
        p_ret=write_ro_memory(p_current_hook_struct->addr,hook_code,remain);
        if(p_ret!=0) return p_ret;
        p_ret=write_ro_memory(p_current_hook_struct->addr+remain,&hook_code[remain],stub->nbytes-remain);
    }else{
        p_ret=write_ro_memory(p_current_hook_struct->addr,hook_code,stub->nbytes);
    }
#endif

    return 0;
}

int inline_hook_uninstall(void *arg)
{
    struct p_hook_struct * p_current_hook_struct=NULL;
	hook_stub * stub=NULL;
    int remain=0;
    int p_ret=-1;

    p_current_hook_struct=(struct p_hook_struct*)arg;
    stub=p_current_hook_struct->stub;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    p_ret = remap_write_range(p_current_hook_struct->addr, stub->orig, stub->nbytes, true);
#else
    remain=PAGE_SIZE-(((unsigned long)p_current_hook_struct->addr)%PAGE_SIZE);
    //Double Page
    if(remain<stub->nbytes){
        p_ret=write_ro_memory(p_current_hook_struct->addr,stub->orig,remain);
        if(p_ret!=0){
            return p_ret;
        }
        p_ret=write_ro_memory(p_current_hook_struct->addr+remain,&stub->orig[remain],stub->nbytes-remain);
    }else{
        p_ret=write_ro_memory(p_current_hook_struct->addr,stub->orig,stub->nbytes);
    }
#endif
    return 0;
}

#endif

