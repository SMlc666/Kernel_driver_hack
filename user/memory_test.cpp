#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "driver.hpp"

int main(int argc, char const *argv[])
{
    printf("[+] Starting memory allocation/deallocation test...\n");

    if (!driver->authenticate())
    {
        printf("[-] Driver authentication failed. Is the module loaded?\n");
        return 1;
    }
    printf("[+] Driver authenticated.\n");

    pid_t self_pid = getpid();
    driver->set_target_pid(self_pid);
    printf("[+] Testing on current process with PID: %d\n", self_pid);

    // 1. Allocate memory
    size_t alloc_size = getpagesize();
    printf("[+] Attempting to allocate %zu bytes...\n", alloc_size);
    uintptr_t allocated_addr = driver->alloc_memory(alloc_size);

    if (allocated_addr == 0) {
        printf("[-] Memory allocation failed. Kernel returned address 0.\n");
        return 1;
    }
    printf("[+] Memory allocated successfully at address: 0x%lx\n", allocated_addr);

    // 2. Write to the allocated memory
    const char* test_string = "Hello from memory_test!";
    size_t test_string_len = strlen(test_string) + 1;
    printf("[+] Writing test string: \"%s\"\n", test_string);
    
    if (!driver->write(allocated_addr, (void*)test_string, test_string_len)) {
        printf("[-] Failed to write to allocated memory via driver.\n");
        driver->free_memory(allocated_addr, alloc_size);
        return 1;
    }
    printf("[+] Write successful.\n");

    // 3. Read back from the memory to verify
    char read_buffer[256] = {0};
    printf("[+] Reading back from allocated memory...\n");
    if (!driver->read(allocated_addr, read_buffer, test_string_len)) {
        printf("[-] Failed to read from allocated memory via driver.\n");
        driver->free_memory(allocated_addr, alloc_size);
        return 1;
    }
    printf("[+] Read successful. Read buffer: \"%s\"\n", read_buffer);

    // 4. Compare results
    if (strcmp(test_string, read_buffer) == 0) {
        printf("[+] SUCCESS: Read data matches written data.\n");
    } else {
        printf("[-] FAILURE: Read data does not match written data.\n");
        driver->free_memory(allocated_addr, alloc_size);
        return 1;
    }

    // 5. Free the memory
    printf("[+] Attempting to free memory at 0x%lx...\n", allocated_addr);
    if (!driver->free_memory(allocated_addr, alloc_size)) {
        printf("[-] Memory deallocation failed.\n");
        return 1;
    }
    printf("[+] Memory freed successfully.\n");

    printf("\n[+] Memory allocation and deallocation test completed successfully!\n");

    return 0;
}
