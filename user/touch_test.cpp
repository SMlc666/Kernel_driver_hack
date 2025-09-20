#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/input.h>
#include <string.h>
#include <string>
#include "driver.hpp"

#ifndef EVIOCGNAME
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#endif

#ifndef EVIOCGPROP
#define EVIOCGPROP(len) _IOC(_IOC_READ, 'E', 0x09, len)
#endif

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
            if (fd < 0) {
                continue;
            }

            // Check if it's a touchscreen
            unsigned char prop_bits[INPUT_PROP_MAX / 8 + 1] = {0};
            if (ioctl(fd, EVIOCGPROP(sizeof(prop_bits)), prop_bits) < 0) {
                close(fd);
                continue;
            }

            bool is_touchscreen = (prop_bits[INPUT_PROP_DIRECT / 8] & (1 << (INPUT_PROP_DIRECT % 8)));
            if (is_touchscreen) {
                // It's a touchscreen, now get its name
                char name[256];
                if (ioctl(fd, EVIOCGNAME(sizeof(name)), name) < 0) {
                    close(fd);
                    continue;
                }
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


// A simple function to simulate a tap at a given coordinate
void tap(int x, int y) {
    TOUCH_DATA down_data;
    down_data.point_count = 1;
    down_data.is_down = true;
    down_data.points[0].id = 0; // Use touch ID 0
    down_data.points[0].x = x;
    down_data.points[0].y = y;
    down_data.points[0].size1 = 10; // Simulate a small touch area
    down_data.points[0].size2 = 10;
    down_data.points[0].size3 = 10;

    printf("[+] Tapping down at (%d, %d)\n", x, y);
    if (!driver->touch_send(&down_data)) {
        printf("[-] Failed to send touch down event\n");
        return;
    }

    // Keep the touch pressed for 50 milliseconds
    usleep(50000);

    TOUCH_DATA up_data;
    up_data.point_count = 0;
    up_data.is_down = false;
    
    printf("[+] Tapping up\n");
    if (!driver->touch_send(&up_data)) {
        printf("[-] Failed to send touch up event\n");
    }
}

int main() {
    printf("[+] Starting kernel touch API test (RCU Find by Name method)...\n");

    if (!driver->authenticate()) {
        printf("[-] Driver authentication failed. Is the module loaded?\n");
        return 1;
    }
    printf("[+] Driver authenticated.\n");

    std::string device_name = find_touchscreen_device_name();
    if (device_name.empty()) {
        return 1;
    }

    // Use the new method to set the device by its name
    if (!driver->hook_input_device_by_name(device_name.c_str())) {
        printf("[-] Failed to set touch device in driver using its name.\n");
        return 1;
    }
    
    // For this test, we'll assume a common screen resolution.
    int screen_max_x = 1080;
    int screen_max_y = 1920;

    // Wait a couple of seconds to give you time to switch apps to see the tap
    printf("[+] Tapping center of the screen in 3 seconds...\n");
    sleep(3);
    tap(screen_max_x / 2, screen_max_y / 2);

    printf("[+] Tapping top-left corner in 3 seconds...\n");
    sleep(3);
    tap(100, 200);

    printf("[+] Test finished. De-initializing touch.\n");
    driver->touch_deinit();

    return 0;
}
