#include <stdio.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <csignal>
#include <iostream>
#include <vector>
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>

#include "driver.hpp"

// --- Globals ---
static bool g_running = true;
static std::string g_device_name;
static uint64_t g_last_kernel_seq = 0;

// --- Signal Handler ---
void signal_handler(int signum) {
    printf("\nCaught signal %d. Shutting down...\n", signum);
    g_running = false;
}

// --- Helper to find touchscreen ---
// (This is the same helper from touch_comprehensive_test.cpp)
#ifndef EVIOCGNAME
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#endif
#ifndef EVIOCGPROP
#define EVIOCGPROP(len) _IOC(_IOC_READ, 'E', 0x09, len)
#endif

bool find_touchscreen_device() {
    DIR *dir;
    struct dirent *entry;
    dir = opendir("/dev/input/");
    if (dir == NULL) return false;

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "event", 5) == 0) {
            std::string path = std::string("/dev/input/") + entry->d_name;
            int fd = open(path.c_str(), O_RDONLY);
            if (fd < 0) continue;

            unsigned char prop_bits[INPUT_PROP_MAX / 8 + 1] = {0};
            if (ioctl(fd, EVIOCGPROP(sizeof(prop_bits)), prop_bits) < 0) {
                close(fd);
                continue;
            }

            if (prop_bits[INPUT_PROP_DIRECT / 8] & (1 << (INPUT_PROP_DIRECT % 8))) {
                char name[256] = {0};
                ioctl(fd, EVIOCGNAME(sizeof(name)), name);
                g_device_name = name;
                close(fd);
                closedir(dir);
                printf("[+] Found touchscreen: %s\n", g_device_name.c_str());
                return true;
            }
            close(fd);
        }
    }
    closedir(dir);
    return false;
}

// --- Main Test Logic ---
void run_touch_modification_test() {
    printf("--- Running MMAP-based Touch Modification Test ---\n");
    printf("--- Touches will be shifted down by 200 pixels ---\n");

    // 1. Hook device
    if (!driver->hook_input_device(g_device_name.c_str())) {
        printf("[-] Failed to hook device.\n");
        return;
    }

    // 2. Map shared memory
    if (!driver->mmap_shared_memory()) {
        printf("[-] Failed to map shared memory.\n");
        driver->unhook_input_device();
        return;
    }

    // 3. Configure shared memory from user side
    struct SharedTouchMemory* mem = driver->shared_mem;
    mem->user_pid = getpid();
    mem->polling_interval_ms = 5; // Set a 5ms polling rate
    g_last_kernel_seq = mem->kernel_sequence;

    printf("[+] Hooked and mapped. Polling interval: %dms. Press Ctrl+C to stop.\n", mem->polling_interval_ms);

    while (g_running) {
        // Update heartbeat
        mem->last_user_heartbeat = time(NULL);

        // Check for new data from kernel
        if (mem->kernel_sequence > g_last_kernel_seq) {
            __sync_synchronize(); // Memory barrier
            g_last_kernel_seq = mem->kernel_sequence;

            printf("--- New Frame (Seq: %lu) ---\n", g_last_kernel_seq);
            mem->user_command_count = 0; // Clear previous commands

            for (int i = 0; i < mem->kernel_touch_count; ++i) {
                KernelTouchPoint* pt = &mem->kernel_touches[i];
                printf("  Kernel Point %d: ID=%d, Active=%u, Pos=(%d, %d)\n", 
                    i, pt->tracking_id, pt->is_active, pt->x, pt->y);

                // Prepare a command to modify this point
                UserCommand* cmd = &mem->user_commands[mem->user_command_count++];
                cmd->action = ACTION_MODIFY;
                cmd->original_tracking_id = pt->tracking_id;
                cmd->new_data.x = pt->x;
                cmd->new_data.y = pt->y + 200; // The modification logic!
                cmd->new_data.pressure = pt->pressure;
            }

            // Publish commands to kernel
            __sync_synchronize(); // Memory barrier
            mem->user_sequence++;
        }

        usleep(1000); // Sleep 1ms to prevent busy-waiting
    }

    // Cleanup
    driver->unhook_input_device();
    printf("[+] Unhooked device.\n");
}

int main() {
    signal(SIGINT, signal_handler);

    if (!driver->authenticate()) {
        printf("[-] Driver authentication failed. Is the module loaded?\n");
        return 1;
    }
    printf("[+] Driver authenticated.\n");

    if (!find_touchscreen_device()) {
        printf("[-] No touchscreen found. Exiting.\n");
        return 1;
    }

    run_touch_modification_test();

    printf("[+] Test finished.\n");
    return 0;
}
