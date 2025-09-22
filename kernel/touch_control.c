#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/kallsyms.h>

#include "version_control.h"
#include "inline_hook/p_hook.h"
#include "touch_shared.h"
#include "touch_control.h"

// --- Globals ---
static struct SharedTouchMemory *g_shared_mem = NULL;
static struct task_struct *g_injection_thread = NULL;
static uint64_t g_last_processed_user_seq = 0;

static struct input_dev *g_hooked_dev = NULL;
static void *g_input_event_addr = NULL;

// Internal state for parsing multi-touch events
static struct KernelTouchPoint g_internal_touch_state[MAX_TOUCH_POINTS];
static int g_current_slot = 0;

// --- Forward Declarations ---
static void process_user_commands(void);
static void hijacked_input_event_callback(hook_fargs4_t *fargs, void *udata);
struct input_dev *input_find_device(struct input_dev *from, const char *name);

// --- Kernel Thread for Injection ---
static int injection_thread_func(void *data) {
    #define MIN_POLLING_INTERVAL_MS 1
    #define MAX_POLLING_INTERVAL_MS 100
    uint32_t sleep_interval_ms;

    PRINT_DEBUG("[TCTRL] Injection thread started.\n");

    while (!kthread_should_stop()) {
        if (g_shared_mem->user_sequence > g_last_processed_user_seq) {
            smp_rmb(); // Read barrier
            process_user_commands();
            g_last_processed_user_seq = g_shared_mem->user_sequence;
        }

        sleep_interval_ms = g_shared_mem->polling_interval_ms;
        if (sleep_interval_ms < MIN_POLLING_INTERVAL_MS) sleep_interval_ms = MIN_POLLING_INTERVAL_MS;
        if (sleep_interval_ms > MAX_POLLING_INTERVAL_MS) sleep_interval_ms = MAX_POLLING_INTERVAL_MS;
        
        msleep(sleep_interval_ms);
    }

    PRINT_DEBUG("[TCTRL] Injection thread stopped.\n");
    return 0;
}

// --- Core Logic ---
static void process_user_commands(void) {
    int i;
    int count = g_shared_mem->user_command_count;
    if (count > MAX_USER_COMMANDS) count = MAX_USER_COMMANDS; // Sanity check

    for (i = 0; i < count; ++i) {
        struct UserCommand *cmd = &g_shared_mem->user_commands[i];
        // TODO: Implement command processing logic (pass-through, modify, inject)
        // This is complex and needs to reconstruct the event stream for injection.
        // For now, we just print a debug message.
        if (cmd->action == ACTION_MODIFY) {
             PRINT_DEBUG("[TCTRL] TODO: Modify event for ID %d to (%d, %d)\n", cmd->original_tracking_id, cmd->new_data.x, cmd->new_data.y);
        }
    }
}

static void reset_internal_state(void) {
    int i;
    for(i = 0; i < MAX_TOUCH_POINTS; ++i) {
        g_internal_touch_state[i].is_active = 0;
        g_internal_touch_state[i].tracking_id = -1;
        g_internal_touch_state[i].slot = i;
    }
    g_current_slot = 0;
}

static void hijacked_input_event_callback(hook_fargs4_t *fargs, void *udata) {
    struct input_dev *dev = (struct input_dev *)fargs->arg0;
    unsigned int type = (unsigned int)fargs->arg1;
    unsigned int code = (unsigned int)fargs->arg2;
    int value = (int)fargs->arg3;

    // Always intercept events from the hooked device
    if (dev == g_hooked_dev) {
        fargs->skip_origin = 1;

        // Parse MT protocol
        switch(type) {
            case EV_ABS:
                switch(code) {
                    case ABS_MT_SLOT:
                        g_current_slot = value;
                        if (g_current_slot >= MAX_TOUCH_POINTS) g_current_slot = 0;
                        break;
                    case ABS_MT_TRACKING_ID:
                        if (value < 0) { // Touch up
                            g_internal_touch_state[g_current_slot].is_active = 0;
                        } else { // Touch down
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
                    // Frame finished, publish state to shared memory
                    int active_touches = 0;
                    int i;
                    for(i = 0; i < MAX_TOUCH_POINTS; ++i) {
                        if(g_internal_touch_state[i].is_active) {
                            g_shared_mem->kernel_touches[active_touches++] = g_internal_touch_state[i];
                        }
                    }
                    g_shared_mem->kernel_touch_count = active_touches;
                    smp_wmb(); // Write barrier
                    g_shared_mem->kernel_sequence++;
                }
                break;
        }
        return;
    }

    // Let other devices' events pass through
    fargs->skip_origin = 0;
}

// --- Public API ---
int touch_control_init(void *shared_mem_ptr) {
    g_shared_mem = (struct SharedTouchMemory *)shared_mem_ptr;
    reset_internal_state();
    PRINT_DEBUG("[TCTRL] Touch control initialized.\n");
    return 0;
}

void touch_control_exit(void) {
    touch_control_stop_hijack();
    g_shared_mem = NULL;
    PRINT_DEBUG("[TCTRL] Touch control exited.\n");
}

int touch_control_start_hijack(const char *device_name) {
    // Find device by name (simplified, real implementation needs to iterate input_dev list)
    g_hooked_dev = input_find_device(NULL, device_name);
    if (!g_hooked_dev) {
        PRINT_DEBUG("[-] Device '%s' not found.\n", device_name);
        return -1;
    }

    // Hook input_event
    g_input_event_addr = (void *)kallsyms_lookup_name("input_event");
    if (!g_input_event_addr) {
        PRINT_DEBUG("[-] Failed to find address of input_event().\n");
        return -1;
    }
    if (hook_wrap(g_input_event_addr, 4, hijacked_input_event_callback, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] Failed to wrap input_event().\n");
        return -1;
    }

    // Start kernel thread
    g_last_processed_user_seq = g_shared_mem->user_sequence;
    g_injection_thread = kthread_run(injection_thread_func, NULL, "touch_injection_thread");
    if (IS_ERR(g_injection_thread)) {
        PRINT_DEBUG("[-] Failed to create injection thread.\n");
        hook_unwrap(g_input_event_addr, hijacked_input_event_callback, NULL);
        return -1;
    }

    PRINT_DEBUG("[TCTRL] Hijack started for device '%s'.\n", device_name);
    return 0;
}

void touch_control_stop_hijack(void) {
    if (g_injection_thread) {
        kthread_stop(g_injection_thread);
        g_injection_thread = NULL;
    }
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

// Helper to find input device by name
// This is a simplified version. A robust one should iterate the input_dev list.
struct input_dev *input_find_device(struct input_dev *from, const char *name)
{
    struct input_dev *dev = NULL;
    struct input_dev *iter;

    rcu_read_lock();
    list_for_each_entry_rcu(iter, &from->node, node) {
        if (iter->name && !strcmp(iter->name, name)) {
            dev = iter;
            break;
        }
    }
    rcu_read_unlock();

    return dev;
}
