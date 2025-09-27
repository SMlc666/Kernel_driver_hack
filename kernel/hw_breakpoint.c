#include <linux/kernel.h>
#include <linux/stop_machine.h>
#include "hw_breakpoint.h"
#include "version_control.h"

// ARM64 MSR/MRS helpers for debug registers
#define write_dbgbcr(n, val) asm volatile("msr dbgbcr" #n "_el1, %0" : : "r"((u64)val))
#define write_dbgbvr(n, val) asm volatile("msr dbgbvr" #n "_el1, %0" : : "r"((u64)val))

// This function will be executed on every CPU core
static int set_breakpoint_on_cpu(void *info)
{
    PHW_BREAKPOINT_CTL ctl = (PHW_BREAKPOINT_CTL)info;
    u64 bcr_val = 0;

    // Check if we are enabling or disabling
    if (ctl->action) { // 'action' field reused for enable/disable flag
        // Configure DBGBCR for an EL0 instruction breakpoint
        bcr_val |= 1;       // E: Enable breakpoint
        bcr_val |= (0b01 << 1); // PMC: EL0
        bcr_val |= (0b0000 << 20); // BT: Unlinked address match
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

    return 0;
}

// Main handler called by ioctl
int handle_set_hw_breakpoint(PHW_BREAKPOINT_CTL ctl, bool enable)
{
    if (ctl->reg_index < 0 || ctl->reg_index > 3) {
        return -EINVAL;
    }

    // We can reuse the 'action' field to pass the enable/disable flag
    // to the per-cpu function.
    ctl->action = enable;

    // stop_machine will run set_breakpoint_on_cpu on all online CPUs.
    // This blocks until all have completed.
    return stop_machine(set_breakpoint_on_cpu, ctl, NULL);
}
