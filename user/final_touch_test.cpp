#include <stdio.h>
#include <unistd.h>
#include <string>
#include <csignal>
#include <iostream>
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>

#include "driver.hpp"

// --- Globals ---
static bool g_running = true;
static std::string g_device_name;

// --- Signal Handler ---
void signal_handler(int signum) {
    printf("\nCaught signal %d. Shutting down early...\n", signum);
    g_running = false;
}

// --- Helper to find touchscreen (unchanged) ---
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

    printf("\n--- Starting Synchronous In-Kernel Modification Test ---\n");
    if (!driver->hook_input_device(g_device_name.c_str())) {
        printf("[-] Failed to hook device.\n");
        return 1;
    }

    printf("[+] Hook active. Test will run for 15 seconds.\n");
    printf("[+] Please test touch now. Y-coordinate should be shifted down by 200 pixels.\n");

    for (int i = 0; i < 15 && g_running; ++i) {
        sleep(1);
        printf(".");
        fflush(stdout);
    }
    printf("\n");

    driver->unhook_input_device();
    printf("[+] Unhooked device. Test finished.\n");

    return 0;
}