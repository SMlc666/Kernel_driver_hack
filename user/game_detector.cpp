#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <mutex>
#include <csignal>
#include <cstdio>

// For perf_event_open
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

// ================= 全局变量 =================
// 游戏分数
static int64_t g_score = 1000;

// 检测状态 (线程间共享)
static std::string g_status = "SECURE";
static std::mutex g_mutex;

// 控制程序运行
static bool g_running = true;

// ================= 辅助函数 =================

// perf_event_open 系统调用的封装
int perf_event_open_syscall(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// 信号处理，用于优雅地退出程序
void signal_handler(int signum) {
    std::cout << "\nCaught signal " << signum << ". Shutting down...\n";
    g_running = false;
}

// ================= 检测线程 =================

void detector_thread() {
    // --- 硬件性能计数器设置 ---
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CACHE_MISSES; // 监控缓存未命中事件
    pe.disabled = 1;
    pe.exclude_kernel = 0; // 包含内核空间
    pe.exclude_hv = 1;

    // pid = -1, cpu = -1 表示监控所有进程、所有CPU
    int perf_fd = perf_event_open_syscall(&pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);

    if (perf_fd == -1) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status = "DETECTOR FAILED: perf_event_open failed. Check permissions.";
        return;
    }

    long long last_perf_value = 0;
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    read(perf_fd, &last_perf_value, sizeof(long long)); // 读取初始值

    std::cout << "[Detector thread started]...\n";

    while (g_running) {
        // 每100毫秒检测一次
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        long long current_perf_value;
        read(perf_fd, &current_perf_value, sizeof(long long));

        long long delta = current_perf_value - last_perf_value;
        last_perf_value = current_perf_value;

        // 阈值：在100ms内发生超过10000次缓存未命中，这是一个非常强的信号
        const long long THRESHOLD = 10000;
        if (delta > THRESHOLD) {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_status = "READ DETECTED! (High Cache Misses)";
        }
    }

    close(perf_fd);
    std::cout << "[Detector thread stopped]...\n";
}

// ================= 游戏主线程 =================

int main() {
    signal(SIGINT, signal_handler); // 捕获 Ctrl+C

    std::cout << "--- Simple Game with Cheat Detection ---\n";
    std::cout << "This game monitors system-wide hardware cache misses.\n";
    std::cout << "Use your kernel driver to read the score's memory address to trigger the detection.\n";
    std::cout << "(Requires perf_event_paranoid = -1 to work without root)\n\n";

    // 启动后台检测线程
    std::thread t(detector_thread);

    while (g_running) {
        // 简单的游戏逻辑：分数每秒变化
        g_score += 10;

        // 打印游戏状态和检测结果
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            printf("Score: %-10lld | Address: %p | Status: %s\n", (long long)g_score, (void*)&g_score, g_status.c_str());
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    t.join(); // 等待检测线程结束
    std::cout << "Game over.\n";

    return 0;
}
