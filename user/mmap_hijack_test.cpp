#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "driver.hpp"

// This struct must match the one in the kernel driver for the test
struct TestSharedMemory {
    volatile uint64_t magic_value;
};

int main() {
    printf("--- MMAP Hijack Test ---\n");

    int fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open device");
        return 1;
    }
    printf("[+] Opened '%s' successfully.\n", DEVICE_NAME);

    // 1. Authenticate with the driver
    if (!driver->authenticate()) {
        printf("[-] Driver authentication failed.\n");
        close(fd);
        return 1;
    }
    printf("[+] Authenticated with driver successfully.\n");

    // 2. mmap the shared memory
    printf("[+] Attempting to mmap shared memory...\n");
    struct TestSharedMemory *shared_area = (struct TestSharedMemory *)mmap(
        NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0
    );

    if (shared_area == MAP_FAILED) {
        perror("[-] mmap failed");
        close(fd);
        return 1;
    }
    printf("[+] mmap successful. Shared area at %p\n", shared_area);

    // 3. Write a magic value from user space
    uint64_t magic = 0xDEADBEEFCAFEBABE;
    shared_area->magic_value = magic;
    printf("[+] User space wrote magic value: 0x%llx\n", magic);

    // 4. Ask kernel to verify the value
    printf("[+] Sending IOCTL to kernel for verification...\n");
    ioctl(fd, 0x817); // OP_VERIFY_MMAP
    printf("[+] Check dmesg for the kernel's output.\n");

    // 5. Read the value back from user space to confirm
    uint64_t value_read_back = shared_area->magic_value;
    printf("[+] User space read back value: 0x%llx\n", value_read_back);

    // 6. Final verification
    if (value_read_back == magic) {
        printf("\n[SUCCESS] Values match! mmap hijack is working.\n");
    } else {
        printf("\n[FAILURE] Mismatch! Read 0x%llx but expected 0x%llx.\n", value_read_back, magic);
    }

    // Cleanup
    munmap(shared_area, getpagesize());
    close(fd);

    return 0;
}
