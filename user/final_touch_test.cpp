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

// --- Main Test Logic (v3) ---
void run_touch_modification_test() {
    printf("--- Running MMAP-based Touch Modification Test (v3 - Explicit UP) ---\n");
    printf("--- Touches will be shifted down by 200 pixels ---\n");

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

    // State tracking for user-space to detect UP events
    KernelTouchPoint prev_touch_state[MAX_TOUCH_POINTS] = {0};

    printf("[+] Hooked and mapped. Polling interval: %dms. Press Ctrl+C to stop.\n", mem->polling_interval_ms);

    while (g_running) {
        mem->last_user_heartbeat = time(NULL);

        while (mem->user_read_idx < mem->kernel_write_idx) {
            __sync_synchronize(); // Barrier before reading kernel data

            const struct TouchFrame* frame = &mem->kernel_frames[mem->user_read_idx % KERNEL_BUFFER_FRAMES];
            mem->user_command_count = 0;

            // NEW LOGIC: Iterate all slots to compare current and previous state
            for (int slot_idx = 0; slot_idx < MAX_TOUCH_POINTS; ++slot_idx) {
                const KernelTouchPoint* current_pt = &frame->touches[slot_idx];
                const KernelTouchPoint* prev_pt = &prev_touch_state[slot_idx];

                if (current_pt->is_active) {
                    // This slot is active. It's either a new touch or a move.
                    // Send a MODIFY command.
                    UserCommand* cmd = &mem->user_commands[mem->user_command_count++];
                    cmd->action = ACTION_MODIFY;
                    cmd->slot = current_pt->slot;
                    cmd->new_data.tracking_id = current_pt->tracking_id;
                    cmd->new_data.x = current_pt->x;
                    cmd->new_data.y = current_pt->y + 200; // The modification
                    cmd->new_data.pressure = current_pt->pressure;

                } else if (prev_pt->is_active) {
                    // This slot is NOT active now, but WAS active before.
                    // This is an explicit "UP" event.
                    UserCommand* cmd = &mem->user_commands[mem->user_command_count++];
                    cmd->action = ACTION_UP;
                    cmd->slot = prev_pt->slot; // Use previous slot info
                }
            }
            
            // After generating all commands for this frame, update the previous state for the next iteration
            memcpy(prev_touch_state, frame->touches, sizeof(frame->touches));

            // If we generated any commands, publish them to the kernel
            if (mem->user_command_count > 0) {
                // printf("Processing Frame %lu: Sending %d commands (Down/Move/Up).\n", (unsigned long)mem->user_read_idx, mem->user_command_count);
                __sync_synchronize(); // Barrier before publishing to kernel
                mem->user_sequence++;
            }

            mem->user_read_idx++;
        }

        usleep(1000); // Sleep to prevent busy-waiting when there are no new frames
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
