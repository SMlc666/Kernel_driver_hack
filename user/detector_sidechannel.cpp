#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <numeric>
#include <algorithm>
#include <iomanip> // <-- 添加此头文件

#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "driver.hpp"

// --- 辅助函数 ---

// 高精度计时器
long long time_nanoseconds() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

// perf_event_open 系统调用的封装
int perf_event_open_syscall(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// --- 检测方法实现 ---

// 方法一: 缓存时序攻击
void test_method_1_cache_timing() {
    std::cout << "--- 方法一: 缓存时序攻击 (Cache Timing Attack) ---\\n";

    const int array_size = 256 * 1024; // 1MB, 确保能占据 L1/L2 缓存
    auto sentinel_array = std::make_unique<char[]>(array_size);
    std::fill(sentinel_array.get(), sentinel_array.get() + array_size, 1);

    const int iterations = 1000;
    std::vector<long long> timings;

    // 1. 建立耗时基线
    for (int i = 0; i < iterations; ++i) {
        long long start_time = time_nanoseconds();
        // 访问数据，使其保持在缓存中
        for (int j = 0; j < array_size; j += 64) { // 步长 64 模拟缓存行访问
            volatile char temp = sentinel_array[j];
        }
        long long end_time = time_nanoseconds();
        timings.push_back(end_time - start_time);
    }
    std::sort(timings.begin(), timings.end());
    long long baseline_median_ns = timings[timings.size() / 2];
    std::cout << "[+] 基线已建立: 正常访问耗时中位数约为 " << baseline_median_ns << " 纳秒。\\n";

    // 2. 制造缓存污染
    const int pollution_size = 8 * 1024 * 1024; // 8MB, 足够污染大部分 CPU 缓存
    void* pollution_buffer = mmap(NULL, pollution_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pollution_buffer == MAP_FAILED) {
        perror("[-] 无法分配用于污染缓存的内存");
        return;
    }
    *(char*)pollution_buffer = 'P'; // 确保内存页被映射
    std::cout << "[+] 执行内核读取以污染 CPU 缓存...\\n";
    driver->read((uintptr_t)pollution_buffer, pollution_buffer, pollution_size);
    munmap(pollution_buffer, pollution_size);

    // 3. 再次测量耗时
    long long start_time = time_nanoseconds();
    for (int j = 0; j < array_size; j += 64) {
        volatile char temp = sentinel_array[j];
    }
    long long end_time = time_nanoseconds();
    long long polluted_time_ns = end_time - start_time;

    std::cout << "[+] 缓存污染后访问耗时: " << polluted_time_ns << " 纳秒。\\n\\n";

    // 4. 结论
    double increase_ratio = (double)polluted_time_ns / baseline_median_ns;
    if (increase_ratio > 3.0) { // 耗时增加超过3倍，这是一个非常强的信号
        std::cout << "【!!! 方法一检测成功 !!!】\\n";
        std::cout << "缓存污染后的访问耗时是正常情况的 " << std::fixed << std::setprecision(2) << increase_ratio << " 倍。\\n";
        std::cout << "这强烈表明一次大规模的内存读取操作清空了 CPU 缓存。\\n";
    } else {
        std::cout << "【方法一未检测到明确信号】\\n";
        std::cout << "访问耗时增加不明显，可能需要调整参数或在更安静的系统环境下测试。\\n";
    }
    std::cout << "--- 方法一结束 ---\\n\\n";
}


// 方法二: 硬件性能计数器
void test_method_2_performance_counters() {
    std::cout << "--- 方法二: 硬件性能计数器 (Hardware Performance Counters) ---\\n";

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CACHE_MISSES; // 我们要计数的事件：缓存未命中
    pe.disabled = 1;
    pe.exclude_kernel = 0; // 包括内核空间的事件
    pe.exclude_hv = 1;

    int fd = perf_event_open_syscall(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("[-] perf_event_open 失败");
        std::cerr << "    这通常需要 root 权限或特定的系统配置 (kernel.perf_event_paranoid <= 1)。\\n";
        std::cout << "--- 方法二中止 ---\\n\\n";
        return;
    }

    // 1. 测量正常操作的缓存未命中数
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    // --- 正常操作 ---
    volatile int normal_op = 0;
    for(int i=0; i<100; ++i) normal_op++;
    // --- 结束 ---
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    long long baseline_misses;
    read(fd, &baseline_misses, sizeof(long long));
    std::cout << "[+] 一次轻量级正常操作产生的缓存未命中数: " << baseline_misses << "\\n";


    // 2. 测量内核读取操作的缓存未命中数
    const int read_size = 4 * 1024 * 1024; // 4MB
    void* read_target = mmap(NULL, read_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (read_target == MAP_FAILED) {
        perror("[-] 无法分配用于读取的内存");
        close(fd);
        return;
    }
    *(char*)read_target = 'R';

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    // --- 内核读取 ---
    driver->read((uintptr_t)read_target, read_target, read_size);
    // --- 结束 ---
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    long long kernel_read_misses;
    read(fd, &kernel_read_misses, sizeof(long long));
    std::cout << "[+] 内核读取 " << read_size / (1024*1024) << "MB 内存产生的缓存未命中数: " << kernel_read_misses << "\\n\\n";
    munmap(read_target, read_size);
    close(fd);

    // 3. 结论
    if (kernel_read_misses > baseline_misses * 100 && kernel_read_misses > 1000) { // 阈值设得很高，避免误判
        std::cout << "【!!! 方法二检测成功 !!!】\\n";
        std::cout << "内核读取操作导致的缓存未命中数 (" << kernel_read_misses
                  << ") 远高于正常操作 (" << baseline_misses << ")。\\n";
        std::cout << "这是一个非常直接且可靠的内核级内存访问证据。\\n";
    } else {
        std::cout << "【方法二未检测到明确信号】\\n";
        std::cout << "缓存未命中数的增长不显著。\\n";
    }
    std::cout << "--- 方法二结束 ---\\n\\n";
}


int main() {
    std::cout << "启动侧信道检测方案。部分功能需要 root 权限。\\n";
    std::cout << "=======================================================\\n\\n";

    if (!driver->initialize(getpid())) {
        std::cerr << "[-] 致命错误: 驱动初始化失败。\\n";
        std::cerr << "[-] 内核模块是否已加载？程序中止。\\n";
        return 1;
    }
    std::cout << "[+] 驱动已为自检模式初始化 (PID: " << getpid() << ")。\\n\\n";
    
    // 等待一秒，让系统静默下来，减少噪音
    std::this_thread::sleep_for(std::chrono::seconds(1));

    test_method_1_cache_timing();
    
    std::this_thread::sleep_for(std::chrono::seconds(1));

    test_method_2_performance_counters();

    return 0;
}
