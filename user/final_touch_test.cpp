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
#include <time.h>

#include "driver.hpp"

// --- Globals ---
static bool g_running = true;
static std::string g_device_name;

// --- Signal Handler ---
void signal_handler(int signum) {
    printf("\nCaught signal %d. Shutting down...\n", signum);
    g_running = false;
}

// --- Helper to find touchscreen ---
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

// --- Main Test Logic (Restored for Command Queue Test) ---
void run_command_queue_test() {
    printf("--- Running Command Queue Test (Synchronous Injection) ---\n");
    printf("--- Touches should be passed through without modification ---\n");

    if (!driver->hook_input_device(g_device_name.c_str())) {
        printf("[-] Failed to hook device.\n");
        return;
    }

    if (!driver->mmap_shared_memory()) {
        printf("[-] Failed to map shared memory.\n");
        driver->unhook_input_device();
        return;
    }

    struct SharedTouchMemory* mem = driver->shared_mem;
    mem->user_pid = getpid();
    mem->polling_interval_ms = 8; // Not used by kernel, but set it anyway
    mem->user_read_idx = mem->kernel_write_idx;

    KernelTouchPoint prev_touch_state[MAX_TOUCH_POINTS] = {0};

    printf("[+] Hooked and mapped. Test will run for 15 seconds.\n");

    time_t start_time = time(NULL);
    while (g_running) {
        if (time(NULL) - start_time >= 15) {
            printf("\n[+] 15 second test duration reached. Stopping...\n");
            g_running = false;
            continue;
        }

        while (mem->user_read_idx < mem->kernel_write_idx) {
            __sync_synchronize(); // Barrier before reading kernel data

            const struct TouchFrame* frame = &mem->kernel_frames[mem->user_read_idx % KERNEL_BUFFER_FRAMES];
            mem->user_command_count = 0;

            for (int slot_idx = 0; slot_idx < MAX_TOUCH_POINTS; ++slot_idx) {
                const KernelTouchPoint* current_pt = &frame->touches[slot_idx];
                const KernelTouchPoint* prev_pt = &prev_touch_state[slot_idx];

                if (current_pt->is_active) {
                    UserCommand* cmd = &mem->user_commands[mem->user_command_count++];
                    cmd->action = ACTION_MODIFY;
                    cmd->slot = current_pt->slot;
                    cmd->new_data.tracking_id = current_pt->tracking_id;
                    cmd->new_data.x = current_pt->x;
                    cmd->new_data.y = current_pt->y; // Passthrough test
                    cmd->new_data.pressure = current_pt->pressure;

                } else if (prev_pt->is_active) {
                    UserCommand* cmd = &mem->user_commands[mem->user_command_count++];
                    cmd->action = ACTION_UP;
                    cmd->slot = prev_pt->slot;
                }
            }
            
            memcpy(prev_touch_state, frame->touches, sizeof(frame->touches));

            if (mem->user_command_count > 0) {
                __sync_synchronize(); // Barrier before publishing to kernel
                mem->user_sequence++;
            }

            mem->user_read_idx++;
        }

        usleep(8000); // Sleep for 8ms
    }

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

    run_command_queue_test();

    printf("[+] Test finished.\n");
    return 0;
}
