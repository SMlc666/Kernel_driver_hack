#include <linux/kernel.h>
#include <linux/stop_machine.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <asm/debug-monitors.h>
#include "hw_breakpoint.h"
#include "version_control.h"

// ARM64 MSR/MRS helpers for debug registers
#define write_dbgbcr(n, val) asm volatile("msr dbgbcr" #n "_el1, %0" : : "r"((u64)val))
#define write_dbgbvr(n, val) asm volatile("msr dbgbvr" #n "_el1, %0" : : "r"((u64)val))

#define read_dbgbcr(n, val) asm volatile("mrs %0, dbgbcr" #n "_el1" : "=r"(val))
#define read_dbgbvr(n, val) asm volatile("mrs %0, dbgbvr" #n "_el1" : "=r"(val))

// This function will be executed on every CPU core
static int set_breakpoint_on_cpu(void *info)
{
    PHW_BREAKPOINT_CTL ctl = (PHW_BREAKPOINT_CTL)info;
    u64 bcr_val = 0;
    u64 saved_bcr = 0;

    PRINT_DEBUG("[+] set_breakpoint_on_cpu: CPU %d, reg_index %d, address 0x%lx, action %d\n",
                smp_processor_id(), ctl->reg_index, ctl->address, ctl->action);

    // Validate parameters
    if (ctl->reg_index < 0 || ctl->reg_index > 3) {
        PRINT_DEBUG("[-] Invalid register index: %d\n", ctl->reg_index);
        return -EINVAL;
    }

    // Read current DBGBCR value first (for debugging)
    switch (ctl->reg_index) {
        case 0: read_dbgbcr(0, saved_bcr); break;
        case 1: read_dbgbcr(1, saved_bcr); break;
        case 2: read_dbgbcr(2, saved_bcr); break;
        case 3: read_dbgbcr(3, saved_bcr); break;
    }
    PRINT_DEBUG("[+] Original DBGBCR%d: 0x%llx\n", ctl->reg_index, saved_bcr);

    // Check if we are enabling or disabling
    if (ctl->action) { // 'action' field reused for enable/disable flag
        // Configure DBGBCR for an EL0 instruction breakpoint
        bcr_val |= (1 << 0);       // E: Enable breakpoint
        bcr_val |= (0b01 << 1);    // PMC: EL0
        bcr_val |= (0b0000 << 20);  // BT: Unlinked address match
        bcr_val |= (0b0010 << 5);  // BAS: Byte address select - bits [7:5]

        // For instruction breakpoints, length must be 0 (aligned to instruction boundary)
        // Address should be aligned to 4 bytes
        if (ctl->address & 0x3) {
            PRINT_DEBUG("[-] Breakpoint address not aligned to 4 bytes: 0x%lx\n", ctl->address);
            return -EINVAL;
        }
    }

    // Select the correct register based on index
    switch (ctl->reg_index) {
        case 0:
            write_dbgbvr(0, ctl->address);
            write_dbgbcr(0, bcr_val);
            break;
        case 1:
            write_dbgbvr(1, ctl->address);
            write_dbgbcr(1, bcr_val);
            break;
        case 2:
            write_dbgbvr(2, ctl->address);
            write_dbgbcr(2, bcr_val);
            break;
        case 3:
            write_dbgbvr(3, ctl->address);
            write_dbgbcr(3, bcr_val);
            break;
        default:
            return -EINVAL;
    }

    // Ensure the instruction pipeline is aware of the change
    asm volatile("isb");

    // Verify the write (for debugging)
    u64 verify_bcr = 0;
    switch (ctl->reg_index) {
        case 0: read_dbgbcr(0, verify_bcr); break;
        case 1: read_dbgbcr(1, verify_bcr); break;
        case 2: read_dbgbcr(2, verify_bcr); break;
        case 3: read_dbgbcr(3, verify_bcr); break;
    }
    PRINT_DEBUG("[+] New DBGBCR%d: 0x%llx (expected: 0x%llx)\n", ctl->reg_index, verify_bcr, bcr_val);

    return 0;
}

// Main handler called by ioctl
int handle_set_hw_breakpoint(PHW_BREAKPOINT_CTL ctl, bool enable)
{
    int ret;

    PRINT_DEBUG("[+] handle_set_hw_breakpoint: reg_index %d, address 0x%lx, enable %d\n",
                ctl->reg_index, ctl->address, enable);

    // Validate parameters
    if (!ctl) {
        PRINT_DEBUG("[-] NULL control structure\n");
        return -EINVAL;
    }

    if (ctl->reg_index < 0 || ctl->reg_index > 3) {
        PRINT_DEBUG("[-] Invalid register index: %d\n", ctl->reg_index);
        return -EINVAL;
    }

    if (enable && ctl->address == 0) {
        PRINT_DEBUG("[-] Invalid breakpoint address: 0x%lx\n", ctl->address);
        return -EINVAL;
    }

    // Check if address is in user space (rough check)
    if (enable && ctl->address >= TASK_SIZE) {
        PRINT_DEBUG("[-] Address not in user space: 0x%lx\n", ctl->address);
        return -EINVAL;
    }

    // We can reuse the 'action' field to pass the enable/disable flag
    // to the per-cpu function.
    ctl->action = enable;

    // First, let's try to enable debug access on this CPU
    // This is often needed on ARM64 to access debug registers
    printk(KERN_INFO "Enabling debug access...\n");

    // stop_machine will run set_breakpoint_on_cpu on all online CPUs.
    // This blocks until all have completed.
    PRINT_DEBUG("[+] Calling stop_machine...\n");
    ret = stop_machine(set_breakpoint_on_cpu, ctl, NULL);

    if (ret) {
        PRINT_DEBUG("[-] stop_machine failed: %d\n", ret);
        return ret;
    }

    PRINT_DEBUG("[+] Hardware breakpoint %s successfully\n", enable ? "set" : "cleared");
    return 0;
}
