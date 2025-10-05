#include "driver.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

class SpawnController {
private:
    c_driver* driver;

public:
    SpawnController() {
        driver = new c_driver();
    }

    ~SpawnController() {
        delete driver;
    }

    bool init() {
        if (!driver->initialize(getpid())) {
            std::cout << "[-] Failed to initialize driver" << std::endl;
            return false;
        }
        return true;
    }

    bool set_spawn_suspend(const char* process_name, bool enable = true) {
        bool result = driver->set_spawn_suspend_target(process_name, enable);
        if (result) {
            std::cout << "[+] " << (enable ? "Enabled" : "Disabled")
                      << " spawn suspend for: " << process_name << std::endl;
        } else {
            std::cout << "[-] Failed to set spawn suspend for: " << process_name << std::endl;
        }
        return result;
    }

    bool resume_process(pid_t pid) {
        bool result = driver->resume_process(pid);
        if (result) {
            std::cout << "[+] Resumed process with PID: " << pid << std::endl;
        } else {
            std::cout << "[-] Failed to resume process with PID: " << pid << std::endl;
        }
        return result;
    }

    bool set_multiple_suspend(const std::vector<std::string>& process_names, bool enable = true) {
        bool all_success = true;
        for (const auto& name : process_names) {
            if (!set_spawn_suspend(name.c_str(), enable)) {
                all_success = false;
            }
        }
        return all_success;
    }

    bool is_available() {
        return driver->authenticate();
    }
};

int main(int argc, char* argv[]) {
    SpawnController controller;

    if (!controller.init()) {
        std::cout << "[-] Failed to initialize spawn controller" << std::endl;
        return 1;
    }

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <command> [arguments]" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  suspend <process_name>    - Enable spawn suspend for process" << std::endl;
        std::cout << "  resume <pid>              - Resume suspended process by PID" << std::endl;
        std::cout << "  enable <process_name>     - Enable spawn suspend (same as suspend)" << std::endl;
        std::cout << "  disable <process_name>    - Disable spawn suspend for process" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "suspend" || command == "enable") {
        if (argc < 3) {
            std::cout << "[-] Missing process name" << std::endl;
            return 1;
        }
        controller.set_spawn_suspend(argv[2], true);
    } else if (command == "disable") {
        if (argc < 3) {
            std::cout << "[-] Missing process name" << std::endl;
            return 1;
        }
        controller.set_spawn_suspend(argv[2], false);
    } else if (command == "resume") {
        if (argc < 3) {
            std::cout << "[-] Missing PID" << std::endl;
            return 1;
        }
        pid_t pid = std::stoi(argv[2]);
        controller.resume_process(pid);
    } else {
        std::cout << "[-] Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}