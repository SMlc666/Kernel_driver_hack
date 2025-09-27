#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "driver.hpp"

volatile sig_atomic_t breakpoint_hit = 0;

void sigtrap_handler(int sig) {
    printf("[+] SIGTRAP received! Hardware breakpoint was hit!\n");
    breakpoint_hit = 1;
}

// Test function that we'll set a breakpoint on
void test_function() {
    printf("[-] Inside test_function() - this should be breakpointed\n");
    for (int i = 0; i < 5; i++) {
        printf("  Loop iteration %d\n", i);
        usleep(100000); // 100ms delay
    }
    printf("[-] test_function() completed\n");
}

int main() {
    printf("[*] Hardware Breakpoint Test Program\n");
    printf("[*] PID: %d\n", getpid());

    // Set up signal handler for SIGTRAP
    signal(SIGTRAP, sigtrap_handler);

    // Initialize driver
    if (!driver->initialize(getpid())) {
        printf("[-] Failed to initialize driver\n");
        return 1;
    }
    printf("[+] Driver initialized successfully\n");

    // Get the address of our test function
    uintptr_t func_addr = (uintptr_t)test_function;
    printf("[+] test_function address: 0x%lx\n", func_addr);

    // Set a hardware breakpoint at the beginning of test_function
    printf("[*] Setting hardware breakpoint at register 0, address 0x%lx\n", func_addr);
    if (!driver->set_hw_breakpoint(0, func_addr, c_driver::HW_BREAKPOINT_EXECUTE, 1)) {
        printf("[-] Failed to set hardware breakpoint\n");
        return 1;
    }
    printf("[+] Hardware breakpoint set successfully\n");

    // Now call the function to trigger the breakpoint
    printf("[*] Calling test_function() to trigger breakpoint...\n");
    test_function();

    // Check if breakpoint was hit
    if (breakpoint_hit) {
        printf("[+] Breakpoint test SUCCESSFUL\n");
    } else {
        printf("[-] Breakpoint test FAILED - no SIGTRAP received\n");
    }

    // Clear the breakpoint
    printf("[*] Clearing hardware breakpoint...\n");
    if (!driver->clear_hw_breakpoint(0)) {
        printf("[-] Failed to clear hardware breakpoint\n");
        return 1;
    }
    printf("[+] Hardware breakpoint cleared\n");

    // Test without breakpoint
    printf("[*] Testing without breakpoint...\n");
    breakpoint_hit = 0;
    test_function();

    if (!breakpoint_hit) {
        printf("[+] No unexpected SIGTRAP - test PASSED\n");
    } else {
        printf("[-] Unexpected SIGTRAP - test FAILED\n");
    }

    printf("[*] Hardware breakpoint test completed\n");
    return 0;
}