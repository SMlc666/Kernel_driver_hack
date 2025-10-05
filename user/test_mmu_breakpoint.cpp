#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include "driver.hpp"

// MMU断点访问类型宏
#define BP_ACCESS_READ     0x01
#define BP_ACCESS_WRITE    0x02
#define BP_ACCESS_EXECUTE  0x04
#define BP_ACCESS_RW       (BP_ACCESS_READ | BP_ACCESS_WRITE)
#define BP_ACCESS_ALL      (BP_ACCESS_READ | BP_ACCESS_WRITE | BP_ACCESS_EXECUTE)

// 测试数据
static volatile int test_variable = 0;
static const char* test_string = "Hello, MMU Breakpoint!";

void print_usage(const char* prog_name) {
    printf("Usage: %s <pid> <addr> <size> <access_type>\n", prog_name);
    printf("  pid: Target process PID (0 for current process)\n");
    printf("  addr: Target address (hex)\n");
    printf("  size: Size to monitor\n");
    printf("  access_type: 1=READ, 2=WRITE, 4=EXECUTE, 7=ALL\n");
    printf("\nExamples:\n");
    printf("  %s 0x%lx 4 1  # Monitor read access to test_variable\n", prog_name, (unsigned long)&test_variable);
    printf("  %s <pid> 0x401000 4096 7  # Monitor all access to code page\n", prog_name);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    // 解析参数
    pid_t target_pid = atoi(argv[1]);
    unsigned long target_addr = strtoul(argv[2], NULL, 16);
    size_t size = strtoul(argv[3], NULL, 10);
    int access_type = atoi(argv[4]);

    printf("[+] MMU Breakpoint Test Program\n");
    printf("[+] Target PID: %d\n", target_pid);
    printf("[+] Target Addr: 0x%lx\n", target_addr);
    printf("[+] Size: %zu\n", size);
    printf("[+] Access Type: 0x%x\n", access_type);

    // 如果是当前进程，使用实际PID
    if (target_pid == 0) {
        target_pid = getpid();
        printf("[+] Using current PID: %d\n", target_pid);
    }

    // 初始化驱动
    c_driver driver;
    if (!driver.authenticate()) {
        printf("[-] Failed to authenticate with driver\n");
        return 1;
    }

    printf("[+] Driver initialized successfully\n");

    // 测试1: 添加断点
    printf("\n[+] Test 1: Adding MMU breakpoint...\n");
    c_driver::MMU_BP_CTL ctl;
    ctl.pid = target_pid;
    ctl.addr = target_addr;
    ctl.size = size;
    ctl.access_type = access_type;
    ctl.action = 1; // 添加

    if (!driver.mmu_breakpoint_control(&ctl)) {
        printf("[-] Failed to add MMU breakpoint\n");
        return 1;
    }
    printf("[+] MMU breakpoint added successfully\n");

    // 如果是当前进程，进行一些测试访问
    if (target_pid == getpid()) {
        printf("\n[+] Test 2: Triggering breakpoints...\n");
        
        if (access_type & BP_ACCESS_READ) {
            printf("[+] Reading from monitored address...\n");
            volatile int dummy = *(volatile int*)target_addr;
            printf("[+] Read completed\n");
        }
        
        if (access_type & BP_ACCESS_WRITE) {
            printf("[+] Writing to monitored address...\n");
            *(volatile int*)target_addr = 12345;
            printf("[+] Write completed\n");
        }
        
        // 等待一下让断点处理完成
        sleep(1);
    }

    // 测试3: 列出断点
    printf("\n[+] Test 3: Listing breakpoints...\n");
    std::vector<c_driver::MMU_BP_INFO> breakpoints;
    if (driver.mmu_breakpoint_list(target_pid, breakpoints)) {
        printf("[+] Found %zu breakpoints:\n", breakpoints.size());
        for (size_t i = 0; i < breakpoints.size(); i++) {
            printf("  [%zu] PID: %d, Addr: 0x%lx, Size: %lu, Type: 0x%x, Active: %s, Hits: %lu\n",
                   i,
                   breakpoints[i].pid,
                   breakpoints[i].addr,
                   breakpoints[i].size,
                   breakpoints[i].access_type,
                   breakpoints[i].is_active ? "Yes" : "No",
                   breakpoints[i].hit_count);
        }
    } else {
        printf("[-] Failed to list breakpoints\n");
    }

    // 如果是当前进程，继续测试
    if (target_pid == getpid()) {
        printf("\n[+] Test 4: More access to test hit counting...\n");
        
        for (int i = 0; i < 3; i++) {
            if (access_type & BP_ACCESS_READ) {
                volatile int dummy = *(volatile int*)target_addr;
            }
            if (access_type & BP_ACCESS_WRITE) {
                *(volatile int*)target_addr = i;
            }
            usleep(100000); // 100ms
        }
        
        // 再次查看断点状态
        std::vector<c_driver::MMU_BP_INFO> final_breakpoints;
        if (driver.mmu_breakpoint_list(target_pid, final_breakpoints)) {
            printf("[+] Final breakpoint states:\n");
            for (size_t i = 0; i < final_breakpoints.size(); i++) {
                printf("  [%zu] PID: %d, Addr: 0x%lx, Hits: %lu\n",
                       i,
                       final_breakpoints[i].pid,
                       final_breakpoints[i].addr,
                       final_breakpoints[i].hit_count);
            }
        }
    }

    // 等待用户输入
    printf("\n[+] Press Enter to remove breakpoint and exit...");
    getchar();

    // 测试5: 移除断点
    printf("\n[+] Test 5: Removing MMU breakpoint...\n");
    ctl.action = 2; // 移除
    
    if (driver.mmu_breakpoint_control(&ctl) != 0) {
        printf("[-] Failed to remove MMU breakpoint\n");
    } else {
        printf("[+] MMU breakpoint removed successfully\n");
    }

    printf("[+] Test completed\n");
    
    return 0;
}
