#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <iomanip>
#include <unistd.h>
#include <sys/mman.h>
#include "driver.hpp"

// 高精度计时器
long long time_nanoseconds() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

// 通过读写操作访问缓冲区
void access_buffer(char* buffer, size_t size) {
    volatile char sink = 0;
    for (size_t i = 0; i < size; i += 64) {
        buffer[i] += 1;
        sink += buffer[i];
    }
}

int main() {
    std::cout << "启动高级缓存状态检测程序，以分析 read_safe 的行为。\n";
    std::cout << "=======================================================\n\n";

    if (!driver->initialize(getpid())) {
        std::cerr << "[-] 致命错误: 驱动初始化失败。\n";
        return 1;
    }
    std::cout << "[+] 驱动已初始化。\n";

    // --- 准备工作 ---
    const size_t honeypot_size = 4096; // 4KB
    char* honeypot = (char*)mmap(NULL, honeypot_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (honeypot == MAP_FAILED) { perror("[-] 蜜罐内存分配失败"); return 1; }
    std::fill(honeypot, honeypot + honeypot_size, 1);

    const size_t eviction_size = 8 * 1024 * 1024; // 8MB
    char* eviction_buffer = (char*)mmap(NULL, eviction_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (eviction_buffer == MAP_FAILED) { perror("[-] 驱逐缓冲区分配失败"); munmap(honeypot, honeypot_size); return 1; }
    std::fill(eviction_buffer, eviction_buffer + eviction_size, 2);
    std::cout << "[+] 测试内存准备就绪。\n\n";

    // --- 步骤 1: 测量热缓存访问时间 ---
    std::cout << "--- 步骤 1: 校准缓存访问时间 ---\\n";
    for (int i = 0; i < 100; ++i) access_buffer(honeypot, honeypot_size);
    long long start_time = time_nanoseconds();
    access_buffer(honeypot, honeypot_size);
    long long t_hot = time_nanoseconds() - start_time;
    std::cout << "[+] 热缓存 (Hot Cache) 访问耗时: " << t_hot << " 纳秒。\n";

    // --- 步骤 2: 测量冷缓存访问时间 ---
    for (int i = 0; i < 5; ++i) access_buffer(eviction_buffer, eviction_size);
    start_time = time_nanoseconds();
    access_buffer(honeypot, honeypot_size);
    long long t_cold = time_nanoseconds() - start_time;
    std::cout << "[+] 冷缓存 (Cold Cache) 访问耗时: " << t_cold << " 纳秒。\n\n";

    // --- 步骤 3: 执行 read_safe 并测试其对缓存的影响 ---
    std::cout << "--- 步骤 2: 执行并分析 read_safe ---\\n";
    // 准备工作：先驱逐一次，确保下一次 read_safe 能成功
    for (int i = 0; i < 5; ++i) access_buffer(eviction_buffer, eviction_size);
    std::cout << "[+] (准备) 已将蜜罐从缓存中驱逐，确保 read_safe 调用成功。\n";

    char dummy_buffer[honeypot_size];
    if (!driver->read_safe((uintptr_t)honeypot, dummy_buffer, honeypot_size)) {
        std::cerr << "[-] 驱动 read_safe 操作失败，测试无法继续。\n";
    } else {
        std::cout << "[+] driver->read_safe() 执行成功。\n";
        // 核心测试：在 read_safe 后立刻访问蜜罐，测量耗时
        start_time = time_nanoseconds();
        access_buffer(honeypot, honeypot_size);
        long long t_after = time_nanoseconds() - start_time;
        std::cout << "[+] read_safe 执行后的访问耗时: " << t_after << " 纳秒。\n\n";

        // --- 步骤 4: 分析并得出结论 ---
        std::cout << "--- 结论 ---\\n";
        // 如果 t_after 和 t_cold 很接近（都很慢），说明 read_safe 没有把数据读进缓存
        // 我们用 t_hot 的两倍作为一个简单的“慢”的阈值
        if (t_after > t_hot * 2) {
            std::cout << "【指纹识别成功】: read_safe 表现为一次『非缓存读取』。\n";
            std::cout << "理由: read_safe 操作之后，蜜罐内存依然是冷的（访问耗时 " << t_after << " ns），\n";
            std::cout << "证明了它在读取数据时没有将数据加载到CPU缓存中。\n";
        } else {
            std::cout << "【行为不符】: read_safe 表现为一次『缓存读取』。\n";
            std::cout << "理由: read_safe 操作之后，蜜罐内存是热的（访问耗时 " << t_after << " ns），\n";
            std::cout << "说明它将数据加载到了CPU缓存中，这不符合我们对 read_safe 的预期。\n";
        }
    }

    // --- 清理 ---
    munmap(honeypot, honeypot_size);
    munmap(eviction_buffer, eviction_size);
    return 0;
}