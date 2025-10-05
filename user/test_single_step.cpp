#include <stdio.h>
#include <unistd.h>
#include <vector>
#include "driver.hpp"

void print_registers(const c_driver::user_pt_regs& regs) {
    printf("=== Registers ===\n");
    for (int i = 0; i < 31; i++) {
        printf("X%d: 0x%016lx\n", i, regs.regs[i]);
    }
    printf("SP: 0x%016lx\n", regs.sp);
    printf("PC: 0x%016lx\n", regs.pc);
    printf("PSTATE: 0x%016lx\n", regs.pstate);
    printf("=================\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target_pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    printf("[+] Target PID: %d\n", target_pid);

    // Initialize driver
    if (!driver->initialize(target_pid)) {
        printf("[-] Failed to initialize driver\n");
        return 1;
    }
    printf("[+] Driver initialized\n");

    // Get all threads
    std::vector<c_driver::THREAD_INFO> threads;
    if (!driver->get_all_threads(target_pid, threads)) {
        printf("[-] Failed to enumerate threads\n");
        return 1;
    }

    printf("[+] Found %zu threads:\n", threads.size());
    for (size_t i = 0; i < threads.size(); i++) {
        printf("  [%zu] TID: %d, Name: %s\n", i, threads[i].tid, threads[i].name);
    }

    if (threads.empty()) {
        printf("[-] No threads found\n");
        return 1;
    }

    // Select first thread for single stepping
    pid_t target_tid = threads[0].tid;
    printf("\n[+] Testing single step on TID: %d\n", target_tid);

    // The single-step engine manages thread state internally, so we don't suspend it here.

    // Start single stepping
    printf("[*] Starting single step mode...\n");
    if (!driver->start_single_step(target_tid)) {
        printf("[-] Failed to start single step\n");
        driver->resume_thread(target_tid);
        return 1;
    }
    printf("[+] Single step mode started\n");

    // Get initial register state
    c_driver::user_pt_regs regs;
    printf("[DEBUG] Before get_step_info: target_tid=%d, &target_tid=%p, &regs=%p\n",
           target_tid, (void*)&target_tid, (void*)&regs);

    if (!driver->get_step_info(target_tid, regs)) {
        printf("[-] Failed to get initial register state\n");
    } else {
        printf("\n[+] Initial state:\n");
        print_registers(regs);
    }

    printf("[DEBUG] After get_step_info: target_tid=%d\n", target_tid);

    // Perform single steps
    int num_steps = 5;
    printf("\n[*] Performing %d single steps...\n", num_steps);

    for (int i = 0; i < num_steps; i++) {
        printf("\n--- Step %d ---\n", i + 1);
        printf("[DEBUG] Before step_and_wait: target_tid=%d\n", target_tid);

        // Use the new atomic step-and-wait operation
        if (!driver->step_and_wait(target_tid, regs)) {
            printf("[-] Step-and-wait failed\n");
            break;
        }

        printf("[+] PC after step: 0x%016lx\n", regs.pc);

        // Sleep a bit to see the output
        usleep(500000); // 0.5 seconds
    }

    // Stop single stepping
    printf("\n[*] Stopping single step mode...\n");
    if (!driver->stop_single_step(target_tid)) {
        printf("[-] Failed to stop single step\n");
    } else {
        printf("[+] Single step mode stopped\n");
    }

    // The stop_single_step function already resumes the thread.
    // No need to call resume_thread again.

    printf("\n[+] Test completed successfully\n");
    return 0;
}
