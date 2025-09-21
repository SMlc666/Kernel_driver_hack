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

// 访问缓冲区以预热/污染缓存
// 通过读后写操作来确保缓存行是“脏”的 (Modified state)
void access_buffer(char* buffer, size_t size) {
    // 使用volatile防止编译器过度优化
    volatile char sink;
    for (size_t i = 0; i < size; i += 64) { // 64字节步长以确保接触到每个缓存行
        buffer[i] += 1; 
    }
}

int main() {
    std::cout << "启动针对非缓存内存的 read_safe() 可行性测试。\n";
    std::cout << "=======================================================\n\n";

    // 1. 初始化驱动
    if (!driver->initialize(getpid())) {
        std::cerr << "[-] 致命错误: 驱动初始化失败。程序中止。\n";
        return 1;
    }
    std::cout << "[+] 驱动已为自检模式初始化 (PID: " << getpid() << ")。\n";

    // 2. 分配蜜罐和驱逐缓冲区
    const size_t honeypot_size = 4096;
    char* honeypot = (char*)mmap(NULL, honeypot_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (honeypot == MAP_FAILED) {
        perror("[-] 蜜罐内存分配失败");
        return 1;
    }
    std::fill(honeypot, honeypot + honeypot_size, 1);
    std::cout << "[+] 蜜罐内存已分配: " << (void*)honeypot << "\n";

    const size_t eviction_size = 8 * 1024 * 1024; // 8MB
    char* eviction_buffer = (char*)mmap(NULL, eviction_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (eviction_buffer == MAP_FAILED) {
        perror("[-] 驱逐缓冲区分配失败");
        munmap(honeypot, honeypot_size);
        return 1;
    }
    std::fill(eviction_buffer, eviction_buffer + eviction_size, 2);
    std::cout << "[+] 驱逐缓冲区已分配 (" << eviction_size / (1024*1024) << "MB)\n";
    
    // 3. 确保蜜罐数据被访问过
    access_buffer(honeypot, honeypot_size);

    // 4. 通过“缓存污染”将蜜罐数据从CPU缓存中驱逐出去
    std::cout << "[+] 正在通过污染CPU缓存来驱逐蜜罐数据...\n";
    for (int i = 0; i < 5; ++i) { // 多次迭代以确保效果
        access_buffer(eviction_buffer, eviction_size);
    }
    std::cout << "[+] 缓存驱逐操作完成。\n";

    // 5. 在此之后，立即尝试用 read_safe 读取可能已不在缓存中的蜜罐
    std::cout << "[+] 尝试用 read_safe() 读取已被驱逐的蜜罐内存...\n";
    char dummy_buffer[honeypot_size];
    if (driver->read_safe((uintptr_t)honeypot, dummy_buffer, honeypot_size)) {
        std::cout << "\n【!!! 实验成功 !!!】\n";
        std::cout << "结论: driver->read_safe() 在目标内存不在缓存中时，调用成功了。\n";
        std::cout << "这有力地证明了之前的失败是由于内核为避免缓存一致性冲突而拒绝了操作。\n";
    } else {
        std::cout << "\n【实验失败】\n";
        std::cout << "结论: driver->read_safe() 即使在目标内存大概率不在缓存中时，依然调用失败。\n";
        std::cout << "这说明内核的限制策略更通用，无论缓存状态如何，都禁止对普通RAM使用 ioremap_nocache。\n";
    }

    // 6. 清理
    munmap(honeypot, honeypot_size);
    munmap(eviction_buffer, eviction_size);
    return 0;
}
