#include <linux/input.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "event_hijack.h"
#include "version_control.h"

// --- Global State for Hijacking ---

// Pointer to the original event handler function
static void (*original_event_handler)(struct input_handle *handle, unsigned int type, unsigned int code, int value);

// Handle to the hooked device
static struct input_handle *hooked_handle = NULL;

// Kernel buffer for hijacked events (simple array-based ring buffer)
static EVENT_PACKAGE event_buffer;
static spinlock_t buffer_lock;
static unsigned int buffer_head = 0;
static unsigned int buffer_tail = 0;

// Wait queue for user-space process to sleep on when buffer is empty
static wait_queue_head_t read_wait_queue;

// Flag to indicate if the hook is active
static bool hook_is_active = false;
static DEFINE_MUTEX(hijack_mutex); // Protects against race conditions during hook/unhook

// --- Forward Declarations ---
static int find_and_hook_handler(const char *name);

// --- Core Hijacking Logic ---

/**
 * Our custom event handler that replaces the original one.
 * This function is the entry point for all physical touch events.
 */
void our_hooked_event_handler(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
    unsigned long flags;

    // 1. Lock the buffer
    spin_lock_irqsave(&buffer_lock, flags);

    // 2. Check if the buffer is full
    if (event_buffer.count < MAX_EVENTS_PER_READ) {
        // 3. Store the event in our kernel buffer
        struct input_event *event = &event_buffer.events[event_buffer.count];
        event->type = type;
        event->code = code;
        event->value = value;
        // get_jiffies_64() is preferred for timestamps if needed
        do_gettimeofday(&event->time);
        event_buffer.count++;
    } else {
        // Buffer is full, we could drop the event or log a warning
        // For now, we drop it.
    }

    // 4. Unlock the buffer
    spin_unlock_irqrestore(&buffer_lock, flags);

    // 5. Wake up the sleeping user-space process
    wake_up_interruptible(&read_wait_queue);

    // 6. CRITICAL: Do not call the original handler. This is the hijack.
    return;
}

// --- Public API Implementation ---

void event_hijack_init(void)
{
    spin_lock_init(&buffer_lock);
    init_waitqueue_head(&read_wait_queue);
    PRINT_DEBUG("[HIJACK] Event hijacking subsystem initialized.\n");
}

void event_hijack_exit(void)
{
    do_cleanup_hook();
    PRINT_DEBUG("[HIJACK] Event hijacking subsystem exited.\n");
}

bool is_hook_active(void)
{
    return hook_is_active;
}

int do_hook_input_device(const char *name)
{
    int ret;
    mutex_lock(&hijack_mutex);

    if (hook_is_active) {
        PRINT_DEBUG("[HIJACK] Hook is already active. Please unhook first.\n");
        mutex_unlock(&hijack_mutex);
        return -EBUSY;
    }

    ret = find_and_hook_handler(name);
    if (ret == 0) {
        hook_is_active = true;
        PRINT_DEBUG("[HIJACK] Successfully hooked device '%s'.\n", name);
    } else {
        // Cleanup in case of partial success
        original_event_handler = NULL;
        hooked_handle = NULL;
    }

    mutex_unlock(&hijack_mutex);
    return ret;
}

void do_cleanup_hook(void)
{
    mutex_lock(&hijack_mutex);

    if (!hook_is_active) {
        mutex_unlock(&hijack_mutex);
        return;
    }

    // Restore the original event handler
    if (hooked_handle && original_event_handler) {
        PRINT_DEBUG("[HIJACK] Restoring original event handler for %s.\n", hooked_handle->name);
        hooked_handle->handler->event = original_event_handler;
    }

    // Clear all state
    original_event_handler = NULL;
    hooked_handle = NULL;
    hook_is_active = false;

    // Wake up any sleeping reader so it can exit cleanly
    wake_up_interruptible(&read_wait_queue);

    PRINT_DEBUG("[HIJACK] Hook cleaned up.\n");
    mutex_unlock(&hijack_mutex);
}

int do_read_input_events(PEVENT_PACKAGE user_pkg)
{
    unsigned long flags;
    int ret;

    // Wait until the buffer has events or the hook is disabled
    ret = wait_event_interruptible(read_wait_queue, event_buffer.count > 0 || !hook_is_active);
    if (ret) {
        // Interrupted by a signal
        return -ERESTARTSYS;
    }

    // If we woke up because the hook was disabled and buffer is empty, return error
    if (!hook_is_active && event_buffer.count == 0) {
        return -ESHUTDOWN;
    }

    // Lock, copy data to a temporary package, and clear the buffer
    spin_lock_irqsave(&buffer_lock, flags);
    
    if (copy_to_user(user_pkg, &event_buffer, sizeof(EVENT_PACKAGE))) {
        spin_unlock_irqrestore(&buffer_lock, flags);
        return -EFAULT;
    }
    
    // Reset buffer
    event_buffer.count = 0;

    spin_unlock_irqrestore(&buffer_lock, flags);

    return 0;
}

int do_inject_input_event(struct input_event *event)
{
    struct input_event k_event;

    if (!hook_is_active || !original_event_handler || !hooked_handle) {
        return -EINVAL;
    }

    if (copy_from_user(&k_event, event, sizeof(struct input_event))) {
        return -EFAULT;
    }

    // CRITICAL: Call the original handler to inject the event, bypassing our hook.
    original_event_handler(hooked_handle, k_event.type, k_event.code, k_event.value);

    return 0;
}


// --- Internal Helper Functions ---

/**
 * Finds an input device by name and hooks its 'evdev' handler.
 * This logic is adapted from the project's existing touch.c for robustness.
 */
static int find_and_hook_handler(const char *name)
{
    struct input_dev *dummy_dev = NULL, *target_dev = NULL;
    struct input_handle *target_handle = NULL;
    int ret = 0;

    dummy_dev = input_allocate_device();
    if (!dummy_dev) return -ENOMEM;

    dummy_dev->name = "khack_dummy_device";
    if (input_register_device(dummy_dev)) {
        input_free_device(dummy_dev);
        return -EFAULT;
    }

    rcu_read_lock();
    struct list_head *curr = rcu_dereference(dummy_dev->node.next);
    struct input_dev *dev_iter;
    while (curr != &dummy_dev->node) {
        dev_iter = list_entry(curr, struct input_dev, node);
        if (dev_iter && dev_iter->name && strcmp(dev_iter->name, name) == 0) {
            if (input_get_device(dev_iter)) {
                target_dev = dev_iter;
            }
            break;
        }
        curr = rcu_dereference(curr->next);
    }
    rcu_read_unlock();

    input_unregister_device(dummy_dev);

    if (!target_dev) {
        PRINT_DEBUG("[HIJACK] Device '%s' not found.\n", name);
        return -ENODEV;
    }

    list_for_each_entry(target_handle, &target_dev->h_list, d_node) {
        if (target_handle->handler && target_handle->handler->name && strcmp(target_handle->handler->name, "evdev") == 0) {
            // Found the evdev handle
            hooked_handle = target_handle;
            break;
        }
    }

    input_put_device(target_dev); // We got the device, now we can release it.

    if (!hooked_handle) {
        PRINT_DEBUG("[HIJACK] Could not find evdev handle for device '%s'.\n", name);
        return -ENODEV;
    }

    // We found the handle, now perform the hook
    original_event_handler = hooked_handle->handler->event;
    if (!original_event_handler) {
        PRINT_DEBUG("[HIJACK] Target handle for '%s' has a NULL event handler.\n", name);
        return -EFAULT;
    }

    hooked_handle->handler->event = &our_hooked_event_handler;

    return 0;
}
