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

// --- Main Test Logic ---
void run_touch_modification_test() {
    printf("--- Running MMAP-based Touch Modification Test (v2) ---
");
    printf("--- Touches will be shifted down by 200 pixels ---
");

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
    mem->polling_interval_ms = 1;
    mem->user_read_idx = mem->kernel_write_idx;

    printf("[+] Hooked and mapped. Polling interval: %dms. Press Ctrl+C to stop.\n", mem->polling_interval_ms);

    while (g_running) {
        mem->last_user_heartbeat = time(NULL);

        while (mem->user_read_idx < mem->kernel_write_idx) {
            __sync_synchronize();

            const struct TouchFrame* frame = &mem->kernel_frames[mem->user_read_idx % KERNEL_BUFFER_FRAMES];

            // Reset command count for the new set of commands
            mem->user_command_count = 0;

            // NEW LOGIC: Iterate through all possible slots, not just active ones.
            for (int slot_idx = 0; slot_idx < MAX_TOUCH_POINTS; ++slot_idx) {
                const KernelTouchPoint* pt = &frame->touches[slot_idx];

                // Only generate commands for slots that are currently active.
                if (pt->is_active) {
                    // Optional: Print details for debugging
                    // printf("  Slot %d: Active (ID: %d, Pos: %d,%d)\n", pt->slot, pt->tracking_id, pt->x, pt->y);

                    UserCommand* cmd = &mem->user_commands[mem->user_command_count++];
                    cmd->action = ACTION_MODIFY;
                    cmd->slot = pt->slot;
                    cmd->new_data.tracking_id = pt->tracking_id;
                    cmd->new_data.x = pt->x;
                    cmd->new_data.y = pt->y + 200; // The modification logic!
                    cmd->new_data.pressure = pt->pressure;
                }
            }

            // If there are any active touches, print a summary for the frame.
            if (mem->user_command_count > 0) {
                 printf("Processing Frame %lu: Found %d active touches. Sending commands.\n", (unsigned long)mem->user_read_idx, mem->user_command_count);
            }

            __sync_synchronize();
            mem->user_sequence++;

            mem->user_read_idx++;
        }

        usleep(1000); 
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

    run_touch_modification_test();

    printf("[+] Test finished.\n");
    return 0;
}