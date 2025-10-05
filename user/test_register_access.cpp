#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#include <sys/user.h>
#include "driver.hpp"

// ARM64 user_pt_regs结构定义（简化版）
struct user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

int main() {
    int fd = open("/proc/version", O_RDONLY);
    if (fd < 0) {
        std::cerr << "Failed to open /proc/version: " << strerror(errno) << std::endl;
        return 1;
    }

    // 认证
    if (ioctl(fd, OP_AUTHENTICATE, 0) < 0) {
        std::cerr << "Authentication failed: " << strerror(errno) << std::endl;
        close(fd);
        return 1;
    }
    std::cout << "[+] Authentication successful" << std::endl;

    // 创建一个子进程用于测试
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // 子进程：进入无限循环
        std::cout << "[+] Child process started, PID: " << getpid() << std::endl;
        while (true) {
            sleep(1);
        }
        exit(0);
    } else if (child_pid < 0) {
        std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
        close(fd);
        return 1;
    }

    // 父进程：等待子进程启动
    sleep(2);
    std::cout << "[+] Parent process, child PID: " << child_pid << std::endl;

    // 暂停子进程
    THREAD_CTL tc;
    tc.tid = child_pid;
    tc.action = THREAD_ACTION_SUSPEND;
    
    if (ioctl(fd, OP_THREAD_CTL, &tc) < 0) {
        std::cerr << "Failed to suspend thread: " << strerror(errno) << std::endl;
        kill(child_pid, SIGKILL);
        close(fd);
        return 1;
    }
    std::cout << "[+] Thread suspended successfully" << std::endl;

    // 等待确保暂停完成
    sleep(1);

    // 测试寄存器读取
    struct user_pt_regs regs;
    REG_ACCESS reg_access;
    reg_access.target_pid = child_pid;
    reg_access.regs_buffer = (uintptr_t)&regs;
    reg_access.operation = 0; // 读取

    if (ioctl(fd, OP_REG_ACCESS, &reg_access) < 0) {
        std::cerr << "Failed to read registers: " << strerror(errno) << std::endl;
        kill(child_pid, SIGKILL);
        close(fd);
        return 1;
    }
    std::cout << "[+] Register read successful" << std::endl;

    // 显示一些关键寄存器
    std::cout << "\n=== Current Registers ===" << std::endl;
    std::cout << "PC (Program Counter): 0x" << std::hex << regs.pc << std::dec << std::endl;
    std::cout << "SP (Stack Pointer): 0x" << std::hex << regs.sp << std::dec << std::endl;
    std::cout << "PSTATE: 0x" << std::hex << regs.pstate << std::dec << std::endl;
    std::cout << "X0: 0x" << std::hex << regs.regs[0] << std::dec << std::endl;
    std::cout << "X1: 0x" << std::hex << regs.regs[1] << std::dec << std::endl;
    std::cout << "X30 (LR): 0x" << std::hex << regs.regs[30] << std::dec << std::endl;

    // 测试寄存器写入
    std::cout << "\n=== Testing Register Write ===" << std::endl;
    
    // 保存原始PC值
    uint64_t original_pc = regs.pc;
    
    // 修改X0寄存器
    regs.regs[0] = 0x1234567890ABCDEF;
    std::cout << "[+] Setting X0 to 0x" << std::hex << 0x1234567890ABCDEF << std::dec << std::endl;

    reg_access.operation = 1; // 写入
    if (ioctl(fd, OP_REG_ACCESS, &reg_access) < 0) {
        std::cerr << "Failed to write registers: " << strerror(errno) << std::endl;
        kill(child_pid, SIGKILL);
        close(fd);
        return 1;
    }
    std::cout << "[+] Register write successful" << std::endl;

    // 再次读取验证写入是否成功
    reg_access.operation = 0; // 读取
    if (ioctl(fd, OP_REG_ACCESS, &reg_access) < 0) {
        std::cerr << "Failed to read registers after write: " << strerror(errno) << std::endl;
        kill(child_pid, SIGKILL);
        close(fd);
        return 1;
    }

    std::cout << "\n=== Registers After Write ===" << std::endl;
    std::cout << "X0: 0x" << std::hex << regs.regs[0] << std::dec << std::endl;
    
    if (regs.regs[0] == 0x1234567890ABCDEF) {
        std::cout << "[+] Register write verification SUCCESS!" << std::endl;
    } else {
        std::cout << "[-] Register write verification FAILED!" << std::endl;
    }

    // 恢复线程
    tc.action = THREAD_ACTION_RESUME;
    if (ioctl(fd, OP_THREAD_CTL, &tc) < 0) {
        std::cerr << "Failed to resume thread: " << strerror(errno) << std::endl;
    } else {
        std::cout << "[+] Thread resumed successfully" << std::endl;
    }

    // 清理
    kill(child_pid, SIGKILL);
    wait(NULL);
    close(fd);
    
    std::cout << "[+] Test completed" << std::endl;
    return 0;
}
