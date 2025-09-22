#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/kallsyms.h>
#include <linux/slab.h> // For input_allocate_device
#include <linux/sched/signal.h> // For is_pid_alive

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
static struct input_dev *input_find_device(const char *name);
static bool is_pid_alive(pid_t pid);

// --- Watchdog & PID Liveness Check ---
static bool is_pid_alive(pid_t pid)
{
    struct task_struct *task;
    if (pid <= 0) return false;
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (task) {
        put_task_struct(task);
        return true;
    }
    return false;
}


// --- Kernel Thread for Injection ---
static int injection_thread_func(void *data) {
    #define MIN_POLLING_INTERVAL_MS 1
    #define MAX_POLLING_INTERVAL_MS 100
    #define WATCHDOG_CHECK_INTERVAL_MS 1000
    uint32_t sleep_interval_ms;
	unsigned long last_watchdog_check = jiffies;


    PRINT_DEBUG("[TCTRL] Injection thread started.\n");

    while (!kthread_should_stop()) {
        // --- Watchdog Logic ---
        if (time_after(jiffies, last_watchdog_check + msecs_to_jiffies(WATCHDOG_CHECK_INTERVAL_MS))) {
            if (g_shared_mem->user_pid > 0 && !is_pid_alive(g_shared_mem->user_pid)) {
                PRINT_DEBUG("[TCTRL] Watchdog: Client PID %d is no longer alive. Cleaning up hook.\n", g_shared_mem->user_pid);
                touch_control_stop_hijack();
                // The thread will be stopped by the cleanup function, so we must exit.
                break;
            }
            last_watchdog_check = jiffies;
        }

		// --- Command Processing Logic ---
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
    int i, j, slot;
    int count = g_shared_mem->user_command_count;
    bool active_slots_in_command[MAX_TOUCH_POINTS] = {false};

    if (count > MAX_USER_COMMANDS) count = MAX_USER_COMMANDS;

    // 1. Process all user commands for this frame, injecting modified/new points
    for (i = 0; i < count; ++i) {
        struct UserCommand *cmd = &g_shared_mem->user_commands[i];
        slot = -1;

        // Find the slot associated with this tracking ID from our internal state
        for (j = 0; j < MAX_TOUCH_POINTS; ++j) {
            if (g_internal_touch_state[j].is_active && g_internal_touch_state[j].tracking_id == cmd->original_tracking_id) {
                slot = g_internal_touch_state[j].slot;
                break;
            }
        }

        if (slot != -1 && (cmd->action == ACTION_MODIFY || cmd->action == ACTION_PASS_THROUGH)) {
            input_mt_slot(g_hooked_dev, slot);
            input_report_abs(g_hooked_dev, ABS_MT_TRACKING_ID, cmd->original_tracking_id);
            input_report_abs(g_hooked_dev, ABS_MT_POSITION_X, cmd->new_data.x);
            input_report_abs(g_hooked_dev, ABS_MT_POSITION_Y, cmd->new_data.y);
            input_report_abs(g_hooked_dev, ABS_MT_PRESSURE, cmd->new_data.pressure);
            active_slots_in_command[slot] = true;
        }
    }

    // 2. Process touch-ups for points that are no longer in the command list
    for (i = 0; i < MAX_TOUCH_POINTS; i++) {
        if (g_internal_touch_state[i].is_active && !active_slots_in_command[i]) {
            input_mt_slot(g_hooked_dev, i);
            input_report_abs(g_hooked_dev, ABS_MT_TRACKING_ID, -1); // Report touch up
        }
    }

    // 3. Finalize the frame
    input_sync(g_hooked_dev);
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
    // Find device by name
    g_hooked_dev = input_find_device(device_name);
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

// Helper to find input device by name using the dummy device traversal trick
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


