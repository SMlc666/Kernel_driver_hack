# 1. 声明要编译成模块的目标文件。
#    Kbuild 会自动根据这个名字生成 my_driver.ko
obj-m += my_driver.o

# 2. 声明 my_driver.o 是由哪些源文件编译链接而成的。
my_driver-objs := memory.o process.o hide_proc.o hide_kill.o entry.o touch.o touch_control.o kallsyms_finder.o

# Add inline hook files
EXTRA_CFLAGS += -g -O0 -Wno-error=incompatible-pointer-types -Wno-error=unused-function
my_driver-objs += inline_hook/p_lkrg_main.o
my_driver-objs += inline_hook/p_hmem.o
my_driver-objs += inline_hook/p_hook.o
my_driver-objs += inline_hook/utils/p_memory.o
my_driver-objs += inline_hook/p_transit_stubs.o

# 这就是全部了！不需要 "all:", "clean:", 也不需要 $(MAKE) 命令。