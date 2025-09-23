#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>

#include "version_control.h"
#include "inline_hook/p_hook.h"
#include "touch_shared.h"
#include "touch_control.h"

// --- Globals ---
static DEFINE_SPINLOCK(g_touch_state_lock);
static struct SharedTouchMemory *g_shared_mem = NULL;
static uint64_t g_last_processed_user_seq = 0;

static struct input_dev *g_hooked_dev = NULL;
static void *g_input_event_addr = NULL;

// Internal state for parsing raw physical touch events
static struct KernelTouchPoint g_internal_touch_state[MAX_TOUCH_POINTS];
static int g_current_slot = 0;

// --- Forward Declarations ---
static void process_user_commands(void);
static void hijacked_input_event_callback(hook_fargs4_t *fargs, void *udata);
static struct input_dev *input_find_device(const char *name);

// --- KERNEL THREAD REMOVED FOR THIS TEST ---

// --- Core Logic ---
static void process_user_commands(void) {
    int i;
    // This function is now called synchronously from the hook.
    // We check the sequence number to see if user-space has provided new commands.
    if (g_shared_mem->user_sequence <= g_last_processed_user_seq) {
        return; // No new commands to process.
    }
    
    smp_rmb(); // Read barrier before accessing command data

    int count = g_shared_mem->user_command_count;
    PRINT_DEBUG("[TCTRL_SYNC_INJECT] Processing %d commands for sequence %llu.\n", count, g_shared_mem->user_sequence);

    if (count > MAX_USER_COMMANDS) count = MAX_USER_COMMANDS;

    for (i = 0; i < count; ++i) {
        struct UserCommand *cmd = &g_shared_mem->user_commands[i];

        if (cmd->slot < 0 || cmd->slot >= MAX_TOUCH_POINTS) continue;

        input_mt_slot(g_hooked_dev, cmd->slot);

        switch (cmd->action) {
            case ACTION_MODIFY:
                input_report_abs(g_hooked_dev, ABS_MT_TRACKING_ID, cmd->new_data.tracking_id);
                input_report_abs(g_hooked_dev, ABS_MT_POSITION_X, cmd->new_data.x);
                input_report_abs(g_hooked_dev, ABS_MT_POSITION_Y, cmd->new_data.y);
                input_report_abs(g_hooked_dev, ABS_MT_PRESSURE, cmd->new_data.pressure);
                break;
            
            case ACTION_UP:
                input_report_abs(g_hooked_dev, ABS_MT_TRACKING_ID, -1);
                break;

            default:
                break;
        }
    }

    input_sync(g_hooked_dev);
    g_last_processed_user_seq = g_shared_mem->user_sequence; // Mark commands as processed
    PRINT_DEBUG("[TCTRL_SYNC_INJECT] Finished processing, input_sync called.\n");
}


static void reset_internal_state(void) {
    int i;
    unsigned long flags;
    spin_lock_irqsave(&g_touch_state_lock, flags);
    for(i = 0; i < MAX_TOUCH_POINTS; ++i) {
        g_internal_touch_state[i].is_active = 0;
        g_internal_touch_state[i].tracking_id = -1;
        g_internal_touch_state[i].slot = i;
    }
    g_current_slot = 0;
    spin_unlock_irqrestore(&g_touch_state_lock, flags);
}

static void hijacked_input_event_callback(hook_fargs4_t *fargs, void *udata) {
    struct input_dev *dev = (struct input_dev *)fargs->arg0;
    unsigned int type = (unsigned int)fargs->arg1;
    unsigned int code = (unsigned int)fargs->arg2;
    int value = (int)fargs->arg3;
    unsigned long flags;

    if (dev == g_hooked_dev) {
        // ALWAYS block the original event. We will replace it with our own injected event.
        fargs->skip_origin = 1;

        spin_lock_irqsave(&g_touch_state_lock, flags);

        // Step 1: Parse the physical touch event and update our internal state.
        switch(type) {
            case EV_ABS:
                switch(code) {
                    case ABS_MT_SLOT:
                        g_current_slot = value;
                        if (g_current_slot >= MAX_TOUCH_POINTS) g_current_slot = 0;
                        break;
                    case ABS_MT_TRACKING_ID:
                        if (value < 0) { g_internal_touch_state[g_current_slot].is_active = 0; } 
                        else { 
                            g_internal_touch_state[g_current_slot].is_active = 1;
                            g_internal_touch_state[g_current_slot].tracking_id = value;
                        }
                        break;
                    case ABS_MT_POSITION_X:
                        g_internal_touch_state[g_current_slot].x = value;
                        break;
                    case ABS_MT_POSITION_Y:
                        g_internal_touch_state[g_current_slot].y = value;
                        break;
                    case ABS_MT_PRESSURE:
                        g_internal_touch_state[g_current_slot].pressure = value;
                        break;
                }
                break;
            case EV_SYN:
                if (code == SYN_REPORT) {
                    // A full physical touch frame has been received.
                    
                    // Step 2: Buffer this physical state for the user-space app to read.
                    uint64_t write_idx = g_shared_mem->kernel_write_idx;
                    if (write_idx - g_shared_mem->user_read_idx < KERNEL_BUFFER_FRAMES) {
                        struct TouchFrame* frame = &g_shared_mem->kernel_frames[write_idx % KERNEL_BUFFER_FRAMES];
                        memcpy(frame->touches, g_internal_touch_state, sizeof(g_internal_touch_state));
                        smp_wmb();
                        g_shared_mem->kernel_write_idx++;
                    }

                    // Step 3: Immediately process commands that user-space prepared from the *previous* frame.
                    process_user_commands();
                }
                break;
        }
        
        spin_unlock_irqrestore(&g_touch_state_lock, flags);
        return;
    }

    // Let events from other devices pass through.
    fargs->skip_origin = 0;
}

// --- Public API ---
int touch_control_init(void *shared_mem_ptr) {
    g_shared_mem = (struct SharedTouchMemory *)shared_mem_ptr;
    reset_internal_state();
    g_shared_mem->kernel_write_idx = 0;
    g_shared_mem->user_read_idx = 0;
    PRINT_DEBUG("[TCTRL] Touch control initialized (Sync-Inject Mode).\n");
    return 0;
}

void touch_control_exit(void) {
    touch_control_stop_hijack();
    g_shared_mem = NULL;
    PRINT_DEBUG("[TCTRL] Touch control exited.\n");
}

int touch_control_start_hijack(const char *device_name) {
    g_hooked_dev = input_find_device(device_name);
    if (!g_hooked_dev) {
        PRINT_DEBUG("[-] Device '%s' not found.\n", device_name);
        return -1;
    }

    g_input_event_addr = (void *)kallsyms_lookup_name("input_event");
    if (!g_input_event_addr) {
        PRINT_DEBUG("[-] Failed to find address of input_event().\n");
        return -1;
    }
    if (hook_wrap(g_input_event_addr, 4, hijacked_input_event_callback, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] Failed to wrap input_event().\n");
        return -1;
    }

    // Kernel thread is no longer used in this mode.
    g_last_processed_user_seq = g_shared_mem->user_sequence;

    PRINT_DEBUG("[TCTRL] Hijack started for device '%s' in Sync-Inject mode.\n", device_name);
    return 0;
}

void touch_control_stop_hijack(void) {
    if (g_input_event_addr) {
        hook_unwrap(g_input_event_addr, hijacked_input_event_callback, NULL);
        g_input_event_addr = NULL;
    }
    if (g_hooked_dev) {
        input_put_device(g_hooked_dev);
        g_hooked_dev = NULL;
    }
    reset_internal_state();
    PRINT_DEBUG("[TCTRL] Hijack stopped.\n");
}

// Helper to find input device by name (unchanged)
static struct input_dev *input_find_device(const char *name)
{
    struct input_dev *dev = NULL, *dummy_dev, *dev_iter;
    int ret;

    dummy_dev = input_allocate_device();
    if (!dummy_dev) {
        PRINT_DEBUG("[-] Failed to allocate dummy device.\n");
        return NULL;
    }

    dummy_dev->name = "khack_dummy_device";
    ret = input_register_device(dummy_dev);
    if (ret) {
        PRINT_DEBUG("[-] Failed to register dummy device.\n");
        input_free_device(dummy_dev);
        return NULL;
    }

    rcu_read_lock();
    list_for_each_entry_rcu(dev_iter, &dummy_dev->node, node) {
        if (dev_iter->name && strcmp(dev_iter->name, name) == 0) {
            if (input_get_device(dev_iter)) { // Increment refcount
                dev = dev_iter;
            }
            break;
        }
    }
    rcu_read_unlock();

    input_unregister_device(dummy_dev);

    return dev;
}
