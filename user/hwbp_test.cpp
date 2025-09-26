#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>
#include <unistd.h>
#include <iomanip>
#include "driver.hpp"

// A simple function to be targeted by our hardware breakpoint.
// The noinline attribute is important to ensure the compiler doesn't
// optimize it away. The volatile variable is to ensure the function
// body is not optimized out.
__attribute__((noinline))
void target_function() {
    volatile int i = 0;
    i++;
}

void print_hit_details(const c_driver::HWBP_HIT_ITEM& item) {
    printf("  -> Hit Details:\n");
    printf("     PID: %llu, Time: %llu, Addr: 0x%llx\n",
           (unsigned long long)item.task_id,
           (unsigned long long)item.hit_time,
           (unsigned long long)item.hit_addr);
    printf("     PC: 0x%llx, SP: 0x%llx, PSTATE: 0x%llx\n",
           (unsigned long long)item.regs_info.pc,
           (unsigned long long)item.regs_info.sp,
           (unsigned long long)item.regs_info.pstate);
    if (item.stack_trace_size > 0) {
        printf("     Stack Trace:\n");
        for (int i = 0; i < item.stack_trace_size; ++i) {
            printf("       #%d: 0x%llx\n", i, (unsigned long long)item.stack_trace[i]);
        }
    }
}

int main() {
    std::cout << "--- Hardware Breakpoint (HWBP) Test ---" << std::endl;

    // 1. Initialize driver
    if (!driver->initialize(getpid())) {
        std::cerr << "[-] Driver initialization failed. Is the module loaded?\n";
        return 1;
    }
    std::cout << "[+] Driver initialized for PID: " << getpid() << std::endl;

    // 2. Check HWBP capabilities
    int brps = driver->get_num_brps();
    if (brps <= 0) {
        std::cerr << "[-] Failed to get number of hardware breakpoint registers or none are available.\n";
        return 1;
    }
    std::cout << "[+] Device supports " << brps << " hardware execution breakpoints." << std::endl;

    // 3. Install HWBP on our target function
    uintptr_t target_addr = (uintptr_t)&target_function;
    std::cout << "[+] Setting breakpoint at address: 0x" << std::hex << target_addr << std::dec << std::endl;

    // Install an execution breakpoint of length 4 bytes
    uintptr_t handle = driver->install_hw_breakpoint(target_addr, 4, 0); // Type 0 for execution
    if (handle == 0) {
        std::cerr << "[-] Failed to install hardware breakpoint.\n";
        return 1;
    }
    std::cout << "[+] Hardware breakpoint installed successfully. Handle: 0x" << std::hex << handle << std::dec << std::endl;

    // 4. Trigger the breakpoint
    std::cout << "[+] Calling target function 5 times to trigger the breakpoint..." << std::endl;
    for (int i = 0; i < 5; ++i) {
        target_function();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "[+] Triggers sent." << std::endl;

    // 5. Wait and retrieve hit information
    std::this_thread::sleep_for(std::chrono::seconds(1));

    uint64_t total_hits = 0;
    uint64_t buffered_hits = 0;
    if (!driver->get_hit_info(handle, total_hits, buffered_hits)) {
        std::cerr << "[-] Failed to get hit info." << std::endl;
    } else {
        std::cout << "[+] Hit Info Retrieved:\n";
        std::cout << "    Total Hits: " << total_hits << "\n";
        std::cout << "    Buffered Hits: " << buffered_hits << "\n";
    }

    if (buffered_hits > 0) {
        std::cout << "[+] Retrieving hit details..." << std::endl;
        auto hits = driver->get_hit_details(handle);
        for (const auto& hit : hits) {
            print_hit_details(hit);
        }
    }

    // 6. Test suspend/resume
    std::cout << "[+] Testing suspend/resume..." << std::endl;
    driver->suspend_hw_breakpoint(handle);
    std::cout << "[+] Breakpoint suspended. Calling target function again (should not trigger)..." << std::endl;
    target_function();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    uint64_t total_hits_after_suspend = 0;
    driver->get_hit_info(handle, total_hits_after_suspend, buffered_hits);
    std::cout << "[+] Total hits after suspend: " << total_hits_after_suspend << " (should be same as before)." << std::endl;

    driver->resume_hw_breakpoint(handle);
    std::cout << "[+] Breakpoint resumed. Calling target function again (should trigger)..." << std::endl;
    target_function();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    uint64_t total_hits_after_resume = 0;
    driver->get_hit_info(handle, total_hits_after_resume, buffered_hits);
    std::cout << "[+] Total hits after resume: " << total_hits_after_resume << "." << std::endl;


    // 7. Uninstall the breakpoint
    std::cout << "[+] Uninstalling hardware breakpoint..." << std::endl;
    if (!driver->uninstall_hw_breakpoint(handle)) {
        std::cerr << "[-] Failed to uninstall hardware breakpoint.\n";
        return 1;
    }
    std::cout << "[+] Hardware breakpoint uninstalled successfully." << std::endl;

    std::cout << "\n--- Test Finished ---" << std::endl;

    return 0;
}
