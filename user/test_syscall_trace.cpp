#include "driver.hpp"
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstring>
#include <vector>

int main() {
    std::cout << "System Call Trace Test" << std::endl;

    // 创建驱动实例
    c_driver driver;
    
    // 认证
    if (!driver.authenticate()) {
        std::cerr << "Authentication failed" << std::endl;
        return 1;
    }

    std::cout << "Authenticated successfully" << std::endl;

    // 开始追踪当前进程的系统调用
    if (!driver.start_syscall_trace(getpid())) {
        std::cerr << "Failed to start syscall tracing" << std::endl;
        return 1;
    }

    std::cout << "Started syscall tracing for PID " << getpid() << std::endl;

    // 执行一些系统调用进行测试
    std::cout << "Performing test system calls..." << std::endl;

    // 文件操作测试
    int test_fd = open("/tmp/test_syscall_trace.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (test_fd >= 0) {
        const char* test_data = "Hello, syscall trace!";
        write(test_fd, test_data, strlen(test_data));
        close(test_fd);
        std::cout << "File operations completed" << std::endl;
    }

    // 内存分配测试
    void* ptr = malloc(1024);
    if (ptr) {
        free(ptr);
        std::cout << "Memory operations completed" << std::endl;
    }

    // 休眠测试
    sleep(1);
    std::cout << "Sleep completed" << std::endl;

    // 停止追踪
    if (!driver.stop_syscall_trace()) {
        std::cerr << "Failed to stop syscall tracing" << std::endl;
    } else {
        std::cout << "Stopped syscall tracing" << std::endl;
    }

    // 清理测试文件
    unlink("/tmp/test_syscall_trace.txt");

    std::cout << "Test completed successfully" << std::endl;
    return 0;
}
