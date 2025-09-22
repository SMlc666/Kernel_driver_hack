#include <iostream>
#include <string>
#include <cstdint>
#include <cstdlib> // For strtoull
#include <cstdio>  // For printf
#include "driver.hpp"

void print_usage(const char* prog_name) {
    fprintf(stderr, "A simple utility to read memory from a target process using the kernel driver.\n");
    fprintf(stderr, "Usage: %s <process_name> <hex_address>\n", prog_name);
    fprintf(stderr, "Example: %s com.example.game 0x7ffc123abc\n", prog_name);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char* process_name = argv[1];
    const char* address_str = argv[2];

    // Convert hex string to address
    char* end;
    uintptr_t address = strtoull(address_str, &end, 16);
    if (*end != '\0') {
        fprintf(stderr, "Error: Invalid hex address format: %s\n", address_str);
        return 1;
    }

    // 1. Authenticate with the driver
    if (!driver->authenticate()) {
        fprintf(stderr, "Error: Failed to authenticate with driver. Is the module loaded?\n");
        return 1;
    }

    // 2. Get PID from process name
    pid_t pid = driver->get_pid(process_name);
    if (pid == 0) {
        fprintf(stderr, "Error: Could not find PID for process: %s\n", process_name);
        return 1;
    }
    printf("[+] Found PID for '%s': %d\n", process_name, pid);

    // 3. Set target PID and perform read
    driver->set_target_pid(pid);
    printf("[+] Attempting to read 8 bytes from address 0x%lx...\n", address);

    uint64_t value = 0;
    // Use our most advanced read method
    bool success = driver->read_safe(address, &value, sizeof(value));

    // 4. Print result
    if (success) {
        printf("\n[SUCCESS]\n");
        printf("  Read from 0x%lx\n", address);
        printf("  Value (hex): 0x%016lx\n", value);
        printf("  Value (dec): %lld\n", (long long)value);
    } else {
        printf("\n[FAILED]\n");
        printf("  Could not read memory from address 0x%lx in process %d.\n", address, pid);
        printf("  This could be due to an invalid address or protection issues.\n");
    }

    return 0;
}
