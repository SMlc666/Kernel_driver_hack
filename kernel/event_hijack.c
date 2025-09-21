#include <linux/input.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h> // For kallsyms_lookup_name
#include <linux/slab.h>
#include <linux/rcupdate.h>

#include "event_hijack.h"
#include "version_control.h"
#include "inline_hook/p_hook.h" // For hook_wrap
#include "inline_hook/p_hmem.h" // For hook_get_mem_from_origin

// --- Touch Mode State ---
typedef enum {
    MODE_PASS_THROUGH, // Default mode, events go to the system
    MODE_INTERCEPT     // Intercept mode, events are blocked from the system
} touch_mode;

static touch_mode current_touch_mode = MODE_PASS_THROUGH;
static DEFINE_SPINLOCK(mode_lock);


// --- Global State for Hijacking ---

// The device we want to hijack events from
static struct input_dev *hooked_dev = NULL;

// Kernel buffer for hijacked events
static EVENT_PACKAGE event_buffer;
static spinlock_t buffer_lock;

// Wait queue for user-space process
static wait_queue_head_t read_wait_queue;

// Flag to indicate if the hook is active
static bool hook_is_active = false;
static DEFINE_MUTEX(hijack_mutex);

// Pointer to the original input_event function, retrieved from the hook engine
static void (*original_input_event)(struct input_dev *dev, unsigned int type, unsigned int code, int value) = NULL;

// New state to prevent injection feedback loop
static bool injection_in_progress = false;
static spinlock_t injection_lock;


// --- Core Hijacking Logic ---

/**
 * This is the "before" callback for our hook on input_event.
 * It gets called for EVERY input event in the system.
 */
static void hooked_input_event_callback(hook_fargs4_t *fargs, void *udata)
{
    struct input_dev *dev = (struct input_dev *)fargs->arg0;
    unsigned long flags;
    bool is_injecting;
    touch_mode current_mode;
    struct input_event *event_to_copy;
    unsigned int type, code;
    bool is_syn_report;
    bool should_wake = false;

    // Check if we are currently injecting an event to prevent feedback
    spin_lock_irqsave(&injection_lock, flags);
    is_injecting = injection_in_progress;
    spin_unlock_irqrestore(&injection_lock, flags);

    if (is_injecting) {
        // This is our own event being injected. Let it pass through to the original function.
        return;
    }

    // Check if the event is from the device we are interested in
    if (hook_is_active && dev == hooked_dev) {
        type = (unsigned int)fargs->arg1;
        code = (unsigned int)fargs->arg2;
        is_syn_report = (type == EV_SYN && code == SYN_REPORT);

        // Always copy the event to the user buffer, regardless of mode.
        spin_lock_irqsave(&buffer_lock, flags);
        if (event_buffer.count < MAX_EVENTS_PER_READ) {
            event_to_copy = &event_buffer.events[event_buffer.count];
            event_to_copy->type = type;
            event_to_copy->code = code;
            event_to_copy->value = (int)fargs->arg3;
            do_gettimeofday(&event_to_copy->time);
            event_buffer.count++;
        }

        // A frame is ready if we get a SYN_REPORT or the buffer is full.
        if (is_syn_report || event_buffer.count >= MAX_EVENTS_PER_READ) {
            if (!frame_ready) {
                frame_ready = true;
                should_wake = true;
            }
        }
        spin_unlock_irqrestore(&buffer_lock, flags);

        if (should_wake) {
            wake_up_interruptible(&read_wait_queue);
        }

        // Read the current touch mode to decide the next action
        spin_lock_irqsave(&mode_lock, flags);
        current_mode = current_touch_mode;
        spin_unlock_irqrestore(&mode_lock, flags);

        // If in intercept mode, prevent the original function from being called
        if (current_mode == MODE_INTERCEPT) {
            fargs->skip_origin = 1;
        }
        // In MODE_PASS_THROUGH, we do nothing, and the event flows to the original function.
    }
}

int do_set_touch_mode(unsigned int mode)
{
    unsigned long flags;

    PRINT_DEBUG("[HIJACK] Setting touch mode to %u\n", mode);

    spin_lock_irqsave(&mode_lock, flags);
    if (mode == MODE_PASS_THROUGH || mode == MODE_INTERCEPT) {
        current_touch_mode = (touch_mode)mode;
        spin_unlock_irqrestore(&mode_lock, flags);
        return 0;
    }
    
    spin_unlock_irqrestore(&mode_lock, flags);
    return -EINVAL; // Invalid mode
}

// --- Public API Implementation ---

void event_hijack_init(void)
{
    spin_lock_init(&buffer_lock);
    init_waitqueue_head(&read_wait_queue);
	spin_lock_init(&injection_lock); // Initialize the new lock
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
    struct input_dev *dummy_dev = NULL, *target_dev = NULL;
    void *input_event_addr;
    hook_chain_t *chain;

    mutex_lock(&hijack_mutex);

    if (hook_is_active) {
        PRINT_DEBUG("[HIJACK] Hook is already active. Please unhook first.\n");
        mutex_unlock(&hijack_mutex);
        return -EBUSY;
    }

    // 1. Find the target device by name using the dummy device trick
    dummy_dev = input_allocate_device();
    if (!dummy_dev) {
        mutex_unlock(&hijack_mutex);
        return -ENOMEM;
    }
    dummy_dev->name = "khack_dummy_device";
    if (input_register_device(dummy_dev)) {
        input_free_device(dummy_dev);
        mutex_unlock(&hijack_mutex);
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
        mutex_unlock(&hijack_mutex);
        return -ENODEV;
    }

    // 2. Find the address of the global input_event function
    input_event_addr = (void *)kallsyms_lookup_name("input_event");
    if (!input_event_addr) {
        PRINT_DEBUG("[HIJACK] Failed to find address of input_event().\n");
        input_put_device(target_dev);
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }

    // 3. Install the hook using the inline hook engine
    if (hook_wrap(input_event_addr, 4, hooked_input_event_callback, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[HIJACK] Failed to wrap input_event().\n");
        input_put_device(target_dev);
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }

    // 4. Save state
    hooked_dev = target_dev;
    hook_is_active = true;

    // 5. Get the original function pointer for injection
    chain = hook_get_mem_from_origin(branch_func_addr((u64)input_event_addr));
    if (chain) {
        original_input_event = (void *)chain->hook.relo_addr;
    } else {
        // This is a critical failure, we must unwind
        PRINT_DEBUG("[HIJACK] CRITICAL: Could not retrieve original function pointer after hook.\n");
        hook_unwrap(input_event_addr, hooked_input_event_callback, NULL);
        input_put_device(hooked_dev);
        hooked_dev = NULL;
        hook_is_active = false;
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }

    PRINT_DEBUG("[HIJACK] Successfully hooked input_event() for device '%s'.\n", name);
    mutex_unlock(&hijack_mutex);
    return 0;
}

void do_cleanup_hook(void)
{
    void *input_event_addr;

    mutex_lock(&hijack_mutex);

    if (!hook_is_active) {
        mutex_unlock(&hijack_mutex);
        return;
    }

    // 1. Find address and unwrap the hook
    input_event_addr = (void *)kallsyms_lookup_name("input_event");
    if (input_event_addr) {
        hook_unwrap(input_event_addr, hooked_input_event_callback, NULL);
        PRINT_DEBUG("[HIJACK] Unwrapped input_event().\n");
    }

    // 2. Clear state
    if (hooked_dev) {
        input_put_device(hooked_dev);
        hooked_dev = NULL;
    }
    original_input_event = NULL;
    hook_is_active = false;

    // 3. Wake up any sleeping reader so it can exit cleanly
    wake_up_interruptible(&read_wait_queue);

    PRINT_DEBUG("[HIJACK] Hook cleaned up.\n");
    mutex_unlock(&hijack_mutex);
}

int do_read_input_events(PEVENT_PACKAGE user_pkg)
{
    int ret;
    unsigned long flags;

    // Wait until the buffer has events or the hook is disabled
    ret = wait_event_interruptible(read_wait_queue, event_buffer.count > 0 || !hook_is_active);
    if (ret) {
        return -ERESTARTSYS;
    }

    // If we woke up because the hook was disabled and buffer is empty, return error
    if (!hook_is_active && event_buffer.count == 0) {
        return -ESHUTDOWN;
    }

    // Lock, copy data to user space, and clear the buffer
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
	unsigned long flags;

    if (!hook_is_active || !original_input_event) {
        return -EINVAL;
    }

    if (copy_from_user(&k_event, event, sizeof(struct input_event))) {
        return -EFAULT;
    }

    // Set flag to prevent feedback loop
    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = true;
    spin_unlock_irqrestore(&injection_lock, flags);


    // CRITICAL: Call the original handler to inject the event.
    // We pass hooked_dev because that's the device context we are simulating.
    original_input_event(hooked_dev, k_event.type, k_event.code, k_event.value);

    // Clear flag
    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = false;
    spin_unlock_irqrestore(&injection_lock, flags);

    return 0;
}

int do_inject_input_package(PEVENT_PACKAGE user_pkg)
{
    EVENT_PACKAGE k_pkg;
    unsigned int i;
	unsigned long flags;

    if (!hook_is_active || !original_input_event) {
        return -EINVAL;
    }

    if (copy_from_user(&k_pkg, user_pkg, sizeof(EVENT_PACKAGE))) {
        return -EFAULT;
    }

    if (k_pkg.count > MAX_EVENTS_PER_READ) {
        return -EINVAL; // Avoid buffer overflow
    }

    // Set flag to prevent feedback loop
    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = true;
    spin_unlock_irqrestore(&injection_lock, flags);

    for (i = 0; i < k_pkg.count; i++) {
        struct input_event *ev = &k_pkg.events[i];
        original_input_event(hooked_dev, ev->type, ev->code, ev->value);
    }

    // Clear flag
    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = false;
    spin_unlock_irqrestore(&injection_lock, flags);

    return 0;
}