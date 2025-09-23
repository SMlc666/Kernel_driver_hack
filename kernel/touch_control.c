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
// Most globals are no longer needed for the synchronous test
static struct input_dev *g_hooked_dev = NULL;
static void *g_input_event_addr = NULL;


// --- Forward Declarations ---
static void hijacked_input_event_callback(hook_fargs4_t *fargs, void *udata);
static struct input_dev *input_find_device(const char *name);


// --- Core Logic (New Synchronous Version) ---
static void hijacked_input_event_callback(hook_fargs4_t *fargs, void *udata) {
    struct input_dev *dev = (struct input_dev *)fargs->arg0;
    unsigned int type = (unsigned int)fargs->arg1;
    unsigned int code = (unsigned int)fargs->arg2;
    // The original value is in fargs->arg3. We access it directly.

    // By default, we let the event pass through.
    fargs->skip_origin = 0;

    // We only apply our logic to the specific device we hooked.
    if (dev == g_hooked_dev) {
        
        // Check if this is an absolute position event for the Y-axis.
        if (type == EV_ABS && code == ABS_MT_POSITION_Y) {
            
            // Directly modify the event's value argument.
            // The original input_event function will receive this modified value.
            fargs->arg3 = fargs->arg3 + 200;
            PRINT_DEBUG("[TCTRL_SYNC] Modified Y-pos from %d to %d\n", (int)fargs->arg3 - 200, (int)fargs->arg3);
        }
    }

    // The hook function finishes, and the original input_event continues with our potentially modified arguments.
}


// --- Public API ---
int touch_control_init(void *shared_mem_ptr) {
    // Not much to do here in the simplified version
    PRINT_DEBUG("[TCTRL_SYNC] Touch control initialized (synchronous mode).\n");
    return 0;
}

void touch_control_exit(void) {
    touch_control_stop_hijack();
    PRINT_DEBUG("[TCTRL_SYNC] Touch control exited (synchronous mode).\n");
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

    // We now use our new synchronous callback
    if (hook_wrap(g_input_event_addr, 4, hijacked_input_event_callback, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[-] Failed to wrap input_event().\n");
        return -1;
    }

    // The kernel thread is no longer needed.
    PRINT_DEBUG("[TCTRL_SYNC] Hijack started for device '%s' in synchronous mode.\n", device_name);
    return 0;
}

void touch_control_stop_hijack(void) {
    // The injection thread is no longer running, so no need to stop it.
    if (g_input_event_addr) {
        hook_unwrap(g_input_event_addr, hijacked_input_event_callback, NULL);
        g_input_event_addr = NULL;
    }
    if (g_hooked_dev) {
        input_put_device(g_hooked_dev);
        g_hooked_dev = NULL;
    }
    PRINT_DEBUG("[TCTRL_SYNC] Hijack stopped.\n");
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