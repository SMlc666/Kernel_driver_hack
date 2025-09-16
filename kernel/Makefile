# 1. 声明要编译成模块的目标文件。
#    Kbuild 会自动根据这个名字生成 my_driver.ko
obj-m += my_driver.o

# 2. 声明 my_driver.o 是由哪些源文件编译链接而成的。
my_driver-objs := memory.o process.o hide_proc.o entry.o

# 这就是全部了！不需要 "all:", "clean:", 也不需要 $(MAKE) 命令。