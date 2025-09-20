#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/input.h>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include "driver.hpp"

#ifndef EVIOCGNAME
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#endif

#ifndef EVIOCGPROP
#define EVIOCGPROP(len) _IOC(_IOC_READ, 'E', 0x09, len)
#endif

// Global flag to control the main loop
static bool running = true;

void signal_handler(int signum) {
    printf("\nCaught signal %d. Shutting down...\n", signum);
    running = false;
}

// Function to find the name of the first input device that is a direct touch device (touchscreen)
std::string find_touchscreen_device_name() {
    DIR *dir;
    struct dirent *entry;
    const char *input_dir = "/dev/input/";

    dir = opendir(input_dir);
    if (dir == NULL) {
        perror("[-] Failed to open /dev/input");
        return "";
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "event", 5) == 0) {
            std::string dev_path = std::string(input_dir) + entry->d_name;
            int fd = open(dev_path.c_str(), O_RDONLY);
            if (fd < 0) continue;

            unsigned char prop_bits[INPUT_PROP_MAX / 8 + 1] = {0};
            if (ioctl(fd, EVIOCGPROP(sizeof(prop_bits)), prop_bits) < 0) {
                close(fd);
                continue;
            }

            bool is_touchscreen = (prop_bits[INPUT_PROP_DIRECT / 8] & (1 << (INPUT_PROP_DIRECT % 8)));
            if (is_touchscreen) {
                char name[256] = {0};
                ioctl(fd, EVIOCGNAME(sizeof(name)), name);
                printf("[+] Found touchscreen device: %s (Name: %s)\n", dev_path.c_str(), name);
                close(fd);
                closedir(dir);
                return std::string(name);
            }
            close(fd);
        }
    }
    closedir(dir);
    printf("[-] No touchscreen device found.\n");
    return "";
}

// Background thread to send heartbeats to the kernel driver
void heartbeat_thread() {
    while (running) {
        driver->send_heartbeat();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    printf("[+] Heartbeat thread stopped.\n");
}

int main() {
    printf("[+] Starting full event hijacking test...\n");
    signal(SIGINT, signal_handler); // Handle Ctrl+C for clean exit

    if (!driver->authenticate()) {
        printf("[-] Driver authentication failed. Is the module loaded?\n");
        return 1;
    }
    printf("[+] Driver authenticated.\n");

    std::string device_name = find_touchscreen_device_name();
    if (device_name.empty()) {
        return 1;
    }

    if (!driver->hook_input_device(device_name.c_str())) {
        printf("[-] Failed to hook touch device in driver.\n");
        return 1;
    }

    // Start the heartbeat thread
    std::thread t(heartbeat_thread);
    printf("[+] Heartbeat thread started. Press Ctrl+C to stop.\n");

    EVENT_PACKAGE pkg;
    while (running) {
        // This call will block until events are available or the hook is terminated
        if (!driver->read_input_events(&pkg)) {
            if (running) {
                // If the loop is supposed to be running, this indicates an error or shutdown from the kernel side
                printf("[-] Failed to read events. The hook might have been terminated.\n");
            }
            break;
        }

        // --- Event Modification and Injection ---
        for (unsigned int i = 0; i < pkg.count; ++i) {
            struct input_event *ev = &pkg.events[i];
            if (ev->type == EV_ABS && ev->code == ABS_MT_POSITION_Y) {
                // printf("    Original Y: %d -> Modified Y: %d\n", ev->value, ev->value + 200);
                ev->value += 200;
            }
        }

        // Inject the entire modified package back into the system at once
        if (!driver->inject_input_package(&pkg)) {
            printf("[-] Failed to inject event package.\n");
        }
        // --- End of Logic ---
    }

    printf("[+] Main loop finished. Cleaning up...\n");
    
    // Stop the heartbeat thread
    running = false;
    t.join();

    // Unhook the device
    driver->unhook_input_device();

    printf("[+] Test finished.\n");
    return 0;
}