#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/input.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>
#include <iostream>
#include "driver.hpp"

#ifndef EVIOCGNAME
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#endif

#ifndef EVIOCGPROP
#define EVIOCGPROP(len) _IOC(_IOC_READ, 'E', 0x09, len)
#endif

#ifndef EVIOCGABS
#define EVIOCGABS(abs) _IOR('E', 0x40 + (abs), struct input_absinfo)
#endif

// Global flag to control test loops
static bool running = true;
static std::string g_device_name;
static int g_max_x = 0;
static int g_max_y = 0;

void signal_handler(int signum) {
    printf("\nCaught signal %d. Shutting down...\n", signum);
    running = false;
}

// Find the first input device that is a direct touch device (touchscreen)
bool find_touchscreen_device() {
    DIR *dir;
    struct dirent *entry;
    const char *input_dir = "/dev/input/";

    dir = opendir(input_dir);
    if (dir == NULL) {
        perror("[-] Failed to open /dev/input");
        return false;
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
                
                struct input_absinfo abs_x, abs_y;
                if (ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &abs_x) == 0 &&
                    ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &abs_y) == 0) {
                    g_max_x = abs_x.maximum;
                    g_max_y = abs_y.maximum;
                }

                printf("[+] Found touchscreen device: %s (Name: %s, Res: %dx%d)\n", dev_path.c_str(), name, g_max_x, g_max_y);
                close(fd);
                closedir(dir);
                g_device_name = std::string(name);
                return true;
            }
            close(fd);
        }
    }
    closedir(dir);
    printf("[-] No touchscreen device found.\n");
    return false;
}

// Background thread to send heartbeats to the kernel driver
void heartbeat_thread() {
    while (running) {
        driver->send_heartbeat();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    printf("[+] Heartbeat thread stopped.\n");
}

// --- Test Cases ---

void test_hijack_passthrough() {
    printf("\n--- [Test 2: Hijack in Pass-through Mode] ---\n");
    printf("Touches should be printed here AND work on the system normally.\n");
    printf("Press Ctrl+C to stop.\n");

    if (!driver->hook_input_device(g_device_name.c_str())) return;
    driver->set_touch_mode(c_driver::MODE_PASS_THROUGH);
    
    running = true;
    std::thread t(heartbeat_thread);
    EVENT_PACKAGE pkg;
    while(running) {
        if (driver->read_input_events(&pkg)) {
            printf("Read %u events. System should have handled them.\n", pkg.count);
        } else {
            if (running) printf("[-] Failed to read events.\n");
            break;
        }
    }
    t.join();
    driver->unhook_input_device();
}

void test_hijack_intercept() {
    printf("\n--- [Test 3: Hijack in Intercept Mode] ---\n");
    printf("Touches should be printed here but have NO effect on the system.\n");
    printf("Press Ctrl+C to stop.\n");

    if (!driver->hook_input_device(g_device_name.c_str())) return;
    driver->set_touch_mode(c_driver::MODE_INTERCEPT);

    running = true;
    std::thread t(heartbeat_thread);
    EVENT_PACKAGE pkg;
    while(running) {
        if (driver->read_input_events(&pkg)) {
            printf("Intercepted %u events. System should NOT have handled them.\n", pkg.count);
        } else {
            if (running) printf("[-] Failed to read events.\n");
            break;
        }
    }
    t.join();
    driver->unhook_input_device();
}

void test_hijack_modify() {
    printf("\n--- [Test 4: Hijack and Modify (Add 200 to Y-axis)] ---\n");
    printf("Touches on the screen should be shifted down by 200 pixels.\n");
    printf("Press Ctrl+C to stop.\n");

    if (g_max_y == 0) {
        printf("[-] Screen dimensions not found, cannot run modify test.\n");
        return;
    }

    if (!driver->hook_input_device(g_device_name.c_str())) return;
    
    // Explicitly set intercept mode for modification
    driver->set_touch_mode(c_driver::MODE_INTERCEPT);
    printf("[+] Set mode to INTERCEPT.\n");

    running = true;
    std::thread t(heartbeat_thread);
    EVENT_PACKAGE pkg;
    while(running) {
        if (driver->read_input_events(&pkg)) {
            for (unsigned int i = 0; i < pkg.count; ++i) {
                struct input_event *ev = &pkg.events[i];
                if (ev->type == EV_ABS && (ev->code == ABS_MT_POSITION_Y || ev->code == ABS_Y)) {
                    ev->value = ev->value + 200;
                    // Clamp the value to prevent it from going off-screen
                    if (ev->value > g_max_y) {
                        ev->value = g_max_y;
                    }
                }
            }
            driver->inject_input_package(&pkg);
        } else {
            if (running) printf("[-] Failed to read events.\n");
            break;
        }
    }
    t.join();
    driver->unhook_input_device();
}

void test_watchdog() {
    printf("\n--- [Test 5: Watchdog Timeout] ---\n");
    printf("Hooking device without sending heartbeats.\n");
    if (!driver->hook_input_device(g_device_name.c_str())) return;

    printf("[+] Hooked. Waiting for 7 seconds for the 5-second watchdog to trigger...\n");
    sleep(7);

    printf("[+] Attempting to read events now. This should fail.\n");
    EVENT_PACKAGE pkg;
    if (driver->read_input_events(&pkg)) {
        printf("[-] Test FAILED. Read events successfully after timeout.\n");
        driver->unhook_input_device();
    } else {
        printf("[+] Test PASSED. Failed to read events as expected (hook was auto-cleaned).\n");
    }
}


void print_menu() {
    printf("\n========== Comprehensive Touch Test Menu ==========\n");
    printf("Device: %s (%dx%d)\n", g_device_name.c_str(), g_max_x, g_max_y);
    printf("---------------------------------------------------\n");
    printf(" 1. Hijack API: Pass-through Mode (Events work normally)\n");
    printf(" 2. Hijack API: Intercept Mode (Events are blocked)\n");
    printf(" 3. Hijack API: Modify Mode (Mirror X-axis)\n");
    printf(" 4. Watchdog Test (Auto-unhook after 5s)\n");
    printf(" 0. Exit\n");
    printf("===================================================\n");
    printf("Enter your choice: ");
}

int main() {
    signal(SIGINT, signal_handler);

    if (!driver->authenticate()) {
        printf("[-] Driver authentication failed. Is the module loaded?\n");
        return 1;
    }
    printf("[+] Driver authenticated.\n");

    if (!find_touchscreen_device()) {
        return 1;
    }

    int choice;
    while (true) {
        print_menu();
        std::cin >> choice;
        if(std::cin.fail()){
            std::cin.clear();
            std::cin.ignore(10000,'\n');
            choice = -1;
        }

        switch (choice) {
            case 1: test_hijack_passthrough(); break;
            case 2: test_hijack_intercept(); break;
            case 3: test_hijack_modify(); break;
            case 4: test_watchdog(); break;
            case 0: printf("Exiting.\n"); return 0;
            default: printf("Invalid choice. Please try again.\n"); break;
        }
        // Reset signal flag in case it was triggered during a test
        running = true; 
    }

    return 0;
}
