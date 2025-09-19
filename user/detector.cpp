#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <vector>
#include "driver.hpp" // 引入驱动头文件

// --- 核心检测逻辑所需的辅助函数 ---

// 通过 /proc/self/pagemap 获取一个虚拟地址对应的物理页帧号 (PFN)
uint64_t get_pfn(void* vaddr) {
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) { return 0; }

    uint64_t vpage_index = (uint64_t)vaddr / getpagesize();
    uint64_t pagemap_offset = vpage_index * sizeof(uint64_t);
    uint64_t pagemap_entry;

    if (pread(pagemap_fd, &pagemap_entry, sizeof(pagemap_entry), pagemap_offset) != sizeof(pagemap_entry)) {
        close(pagemap_fd);
        return 0;
    }
    close(pagemap_fd);

    if (!((pagemap_entry >> 63) & 1)) { return 0; } // 检查页是否存在
    return pagemap_entry & ((1ULL << 55) - 1);
}

// 通过 /proc/kpageflags 和 PFN 检查页的“访问位”是否被设置
// KPF_REFERENCED 在内核标志中的索引是 2
#define KPF_REFERENCED (1ULL << 2)
bool is_page_accessed(int kpageflags_fd, uint64_t pfn) {
    if (pfn == 0) { return false; }

    uint64_t kpageflags_offset = pfn * sizeof(uint64_t);
    uint64_t kpageflags_entry;

    if (pread(kpageflags_fd, &kpageflags_entry, sizeof(kpageflags_entry), kpageflags_offset) != sizeof(kpageflags_entry)) {
        return false;
    }
    return (kpageflags_entry & KPF_REFERENCED) != 0;
}

// 通过 /proc/self/clear_refs 请求内核清空本进程的“访问位”
void clear_referenced_bits() {
    int clear_refs_fd = open("/proc/self/clear_refs", O_WRONLY);
    if (clear_refs_fd < 0) { return; }
    // 写入 "1" 表示清空私有映射的访问位
    write(clear_refs_fd, "1", 1);
    close(clear_refs_fd);
}

// --- 主程序 ---

int main() {
    printf("启动高级混合检测方案。本程序需要以 root 权限运行。\n");
    printf("=======================================================\n\n");

    if (getuid() != 0) {
        printf("错误: 本程序必须以 root 身份运行才能访问 /proc/kpageflags。\n");
        return 1;
    }

    // 初始化驱动
    if (!driver->initialize(getpid())) {
        fprintf(stderr, "[-] 致命错误: 驱动初始化失败。\n");
        fprintf(stderr, "[-] 内核模块是否已加载？程序中止。\n");
        return 1;
    }
    printf("[+] 驱动已为自检模式初始化 (PID: %d)。\n\n", getpid());

    long page_size = getpagesize();
    
    // --- 步骤 1: 设置陷阱 ---
    printf("--- 步骤 1: 设置陷阱 ---\n");

    // 分配蜜罐内存页
    void* honeypot = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (honeypot == MAP_FAILED) {
        perror("[-] 蜜罐内存分配失败");
        return 1;
    }
    printf("[+] 蜜罐内存已分配，地址: %p\n", honeypot);

    // 写入数据以确保页面被换入 RAM
    *(char*)honeypot = 'X';
    
    // 打开 kpageflags 文件描述符，后续会用到
    int kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
    if (kpageflags_fd < 0) {
        perror("[-] 打开 /proc/kpageflags 失败");
        munmap(honeypot, page_size);
        return 1;
    }

    // 请求内核将此页面从 RAM 中换出
    printf("[+] 请求内核将蜜罐页换出 RAM (madvise)...");
    if (madvise(honeypot, page_size, MADV_DONTNEED) != 0) {
        perror("    [-] madvise 调用失败");
    }
    
    // 请求内核清空此进程所有页面的“访问位”
    printf("\n[+] 请求内核清空'访问位' (clear_refs)...");
    clear_referenced_bits();
    
    // 等待内核响应
    usleep(200000);
    printf("\n");

    // --- 步骤 2: 验证陷阱是否设置成功 ---
    printf("--- 步骤 2: 验证陷阱状态 ---\n");
    
    // 验证 mincore 陷阱
    std::vector<unsigned char> vec(1);
    mincore(honeypot, page_size, vec.data());
    bool is_resident = vec[0] & 1;
    if (!is_resident) {
        printf("[+] [成功] mincore 陷阱已生效: 页面当前不在 RAM 中。\n");
    } else {
        printf("[-] [失败] mincore 陷阱未生效: 页面仍在 RAM 中。\n");
    }

    // 验证 kpageflags 陷阱
    uint64_t pfn = get_pfn(honeypot);
    bool is_accessed = is_page_accessed(kpageflags_fd, pfn);
    if (!is_accessed) {
        printf("[+] [成功] kpageflags 陷阱已生效: 页面的'访问位'当前为 0。\n");
    } else {
        printf("[-] [失败] kpageflags 陷阱未生效: 页面的'访问位'仍然为 1。\n");
    }
    
    if (is_resident || is_accessed) {
        printf("\n警告: 陷阱未能完美设置，检测结果可能不准确。\n");
    }
    printf("\n");

    // --- 步骤 3: 触发读取 ---
    printf("--- 步骤 3: 通过驱动执行内核级读取 ---\n");
    char read_buffer[8];
    if (driver->read((uintptr_t)honeypot, read_buffer, sizeof(read_buffer))) {
        printf("[+] 驱动读取操作已成功执行。\n\n");
    } else {
        printf("[-] 驱动读取操作失败。\n\n");
    }
    usleep(100000);

    // --- 步骤 4: 检查陷阱结果 ---
    printf("--- 步骤 4: 最终检测 ---\n");

    // 检查 mincore 陷阱是否被触发
    mincore(honeypot, page_size, vec.data());
    if (vec[0] & 1) {
        printf("[!] mincore 检测: [触发] -> 页面被重新加载回了 RAM。\n");
    } else {
        printf("[✓] mincore 检测: [未触发] -> 页面依然不在 RAM 中 (符合预期)。\n");
    }

    // 检查 kpageflags 陷阱是否被触发
    pfn = get_pfn(honeypot); // 重新获取 PFN，以防万一
    if (is_page_accessed(kpageflags_fd, pfn)) {
        printf("[!] kpageflags 检测: [触发] -> 页面的'访问位'被置为 1。\n");
    } else {
        printf("[✗] kpageflags 检测: [未触发] -> 页面的'访问位'仍然为 0。\n");
    }
    printf("\n");

    // --- 最终结论 ---
    printf("--- 结论 ---\n");
    if (!(vec[0] & 1) && is_page_accessed(kpageflags_fd, pfn)) {
        printf("【检测成功！】\n");
        printf("观察到一个独特的作弊指纹：\n");
        printf("  - 内存页本身没有被加载回进程的 RAM 中 (mincore 未触发)。\n");
        printf("  - 但其底层的'访问位'却被设置了 (kpageflags 触发)。\n");
        printf("这个矛盾的现象强烈表明存在一个内核级的、直接的物理内存读取操作。\n");
    } else {
        printf("【未检测到明确信号】\n");
        printf("未能捕捉到预期的'mincore 未触发 & kpageflags 触发'的组合信号。\n");
        printf("这表明该驱动的读取行为非常隐蔽，甚至能绕过对'访问位'的监控。\n");
    }

    // 清理
    close(kpageflags_fd);
    munmap(honeypot, page_size);
    return 0;
}
