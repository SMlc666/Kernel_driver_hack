#include "driver.hpp"
#include <iostream>
#include <unistd.h>
#include <vector>

// Function to add a touch point to the shared buffer
void send_touch_point(c_driver::TOUCH_SHARED_BUFFER* shared_buffer, c_driver::TOUCH_ACTION action, unsigned int slot, int x, int y) {
    if (!shared_buffer) return;

    unsigned int next_head = (shared_buffer->head + 1) % c_driver::TOUCH_BUFFER_POINTS;
    if (next_head == shared_buffer->tail) {
        // Buffer is full, wait for the kernel to process points
        usleep(1000); 
    }

    shared_buffer->points[shared_buffer->head].action = action;
    shared_buffer->points[shared_buffer->head].slot = slot;
    shared_buffer->points[shared_buffer->head].x = x;
    shared_buffer->points[shared_buffer->head].y = y;
    shared_buffer->head = next_head;
}

int main() {
    if (!driver->authenticate()) {
        std::cerr << "[-] Failed to authenticate with the driver." << std::endl;
        return 1;
    }
    std::cout << "[+] Driver authenticated." << std::endl;

    if (!driver->install_touch_hook()) {
        std::cerr << "[-] Failed to install touch hook." << std::endl;
        return 1;
    }
    std::cout << "[+] Touch hook installed." << std::endl;

    c_driver::TOUCH_SHARED_BUFFER* touch_buffer = driver->mmap_touch_buffer();
    if (!touch_buffer) {
        std::cerr << "[-] Failed to map touch buffer." << std::endl;
        driver->uninstall_touch_hook();
        return 1;
    }
    std::cout << "[+] Touch buffer mapped." << std::endl;

    if (!driver->set_touch_mode(c_driver::TOUCH_MODE_EXCLUSIVE_INJECT)) {
        std::cerr << "[-] Failed to set touch mode." << std::endl;
        munmap(touch_buffer, sizeof(c_driver::TOUCH_SHARED_BUFFER));
        driver->uninstall_touch_hook();
        return 1;
    }
    std::cout << "[+] Touch mode set to exclusive inject." << std::endl;

    std::cout << "[*] Simulating a swipe from (500, 500) to (1000, 1000)..." << std::endl;

    // Simulate a touch down event
    send_touch_point(touch_buffer, c_driver::TOUCH_ACTION_DOWN, 0, 500, 500);
    driver->notify_touch_data();
    usleep(20000); // 20ms delay

    // Simulate move events
    for (int i = 1; i <= 50; ++i) {
        int x = 500 + (i * 10);
        int y = 500 + (i * 10);
        send_touch_point(touch_buffer, c_driver::TOUCH_ACTION_MOVE, 0, x, y);
        driver->notify_touch_data();
        usleep(10000); // 10ms delay between move events
    }

    // Simulate a touch up event
    send_touch_point(touch_buffer, c_driver::TOUCH_ACTION_UP, 0, 1000, 1000);
    driver->notify_touch_data();
    
    std::cout << "[+] Swipe simulation finished." << std::endl;
    
    // Give some time for the last event to be processed
    sleep(1);

    // Cleanup
    std::cout << "[*] Cleaning up..." << std::endl;
    driver->set_touch_mode(c_driver::TOUCH_MODE_DISABLED);
    munmap(touch_buffer, sizeof(c_driver::TOUCH_SHARED_BUFFER));
    driver->uninstall_touch_hook();
    std::cout << "[+] Cleanup complete." << std::endl;

    return 0;
}
