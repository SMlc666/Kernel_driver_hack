#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h> // For kallsyms_lookup_name
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h> // For atomic operations

#include "event_hijack.h"
#include "version_control.h"
#include "inline_hook/p_hook.h" // For hook_wrap
#include "inline_hook/p_hmem.h" // For hook_get_mem_from_origin

// --- Global State for Hijacking ---

// The device we want to hijack events from
static struct input_dev *hooked_dev = NULL;

// --- Ring Buffer for passing events to userspace ---
#define RING_BUFFER_SIZE 16 // Power of 2 for efficient modulo
static EVENT_PACKAGE ring_buffer[RING_BUFFER_SIZE];
static atomic_t ring_buffer_head = ATOMIC_INIT(0);
static atomic_t ring_buffer_tail = ATOMIC_INIT(0);
static spinlock_t ring_buffer_lock; // Protects the ring buffer structure

// A temporary buffer to assemble a frame before committing it to the ring buffer
static EVENT_PACKAGE frame_assembly_buffer;
static spinlock_t assembly_lock;

// Wait queue for user-space process
static wait_queue_head_t read_wait_queue;

// --- State for Dual Hooking ---
static bool hook_is_active = false;
static DEFINE_MUTEX(hijack_mutex);

// Flag to prevent injection feedback loop
static bool injection_in_progress = false;
static spinlock_t injection_lock;

// State for HOOK 1 (input_event)
static void *input_event_addr_global = NULL;

// State for HOOK 2 (evdev_event)
static bool evdev_hook_is_active = false;
static void *evdev_event_addr_global = NULL;


// --- Core Hijacking Logic ---

/**
 * HOOK 1: This is the "before" callback for our hook on input_event.
 * Its ONLY purpose is to SNOOP (listen) to events to maintain kernel state
 * and to pass them to userspace. It NEVER blocks the original event.
 */
static void hooked_input_event_callback(hook_fargs4_t *fargs, void *udata)
{
    struct input_dev *dev = (struct input_dev *)fargs->arg0;
    unsigned long flags;
    struct input_event *event_to_copy;
    unsigned int type, code;
    bool is_syn_report;
    bool should_wake = false;
    bool is_injecting;

    // Check if we are currently injecting an event to prevent feedback loop.
    // If so, we must not capture this event and send it back to userspace.
    spin_lock_irqsave(&injection_lock, flags);
    is_injecting = injection_in_progress;
    spin_unlock_irqrestore(&injection_lock, flags);

    if (is_injecting && dev == hooked_dev) {
        fargs->skip_origin = 0; // Let the original event proceed, but do nothing else.
        return;
    }

    // Check if the event is from the device we are interested in
    if (hook_is_active && dev == hooked_dev) {
        type = (unsigned int)fargs->arg1;
        code = (unsigned int)fargs->arg2;
        is_syn_report = (type == EV_SYN && code == SYN_REPORT);

        // Assemble the event into the temporary buffer
        spin_lock_irqsave(&assembly_lock, flags);
        if (frame_assembly_buffer.count < MAX_EVENTS_PER_READ) {
            event_to_copy = &frame_assembly_buffer.events[frame_assembly_buffer.count];
            event_to_copy->type = type;
            event_to_copy->code = code;
            event_to_copy->value = (int)fargs->arg3;
            do_gettimeofday(&event_to_copy->time);
            frame_assembly_buffer.count++;
        }

        // If a frame is complete, commit it to the ring buffer
        if (is_syn_report || frame_assembly_buffer.count >= MAX_EVENTS_PER_READ) {
            int head, new_head;
            
            spin_lock(&ring_buffer_lock);
            
            head = atomic_read(&ring_buffer_head);
            new_head = (head + 1) & (RING_BUFFER_SIZE - 1);

            if (new_head == atomic_read(&ring_buffer_tail)) {
                atomic_set(&ring_buffer_tail, (atomic_read(&ring_buffer_tail) + 1) & (RING_BUFFER_SIZE - 1));
            }

            memcpy(&ring_buffer[head], &frame_assembly_buffer, sizeof(EVENT_PACKAGE));
            atomic_set(&ring_buffer_head, new_head);
            
            spin_unlock(&ring_buffer_lock);

            frame_assembly_buffer.count = 0;
            should_wake = true;
        }
        spin_unlock_irqrestore(&assembly_lock, flags);

        if (should_wake) {
            wake_up_interruptible(&read_wait_queue);
        }
    }
    
    // CRITICAL: We NEVER block the original input_event.
    // This ensures the kernel's input subsystem state is always correct.
    fargs->skip_origin = 0;
}

/**
 * HOOK 2: This is the "before" callback for our hook on evdev_event.
 * Its ONLY purpose is to BLOCK the original, unmodified events from
 * reaching the userspace file descriptor (/dev/input/eventX).
 */
static void hooked_evdev_event_callback(hook_fargs4_t *fargs, void *udata)
{
    struct input_handle *handle = (struct input_handle *)fargs->arg0;
    unsigned long flags;
    bool is_injecting;

    // Check if we are currently injecting an event to prevent feedback
    spin_lock_irqsave(&injection_lock, flags);
    is_injecting = injection_in_progress;
    spin_unlock_irqrestore(&injection_lock, flags);

    // If we are injecting our own event for the hooked device, it MUST be allowed to pass.
    if (is_injecting && handle->dev == hooked_dev) {
        fargs->skip_origin = 0;
        return;
    }

    // If this is a raw, physical event from the device we've hooked, block it.
    if (handle->dev == hooked_dev) {
        fargs->skip_origin = 1; // This is the firewall.
        return;
    }

    // All other events (from other devices) pass through normally.
    fargs->skip_origin = 0;
}


// --- Public API Implementation ---

void event_hijack_init(void)
{
    spin_lock_init(&ring_buffer_lock);
    spin_lock_init(&assembly_lock);
    init_waitqueue_head(&read_wait_queue);
	  spin_lock_init(&injection_lock);
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
    struct input_handle *handle;
    void *evdev_event_addr = NULL;

    mutex_lock(&hijack_mutex);

    if (hook_is_active) {
        PRINT_DEBUG("[HIJACK] Hook is already active. Please unhook first.\n");
        mutex_unlock(&hijack_mutex);
        return -EBUSY;
    }

    struct input_dev *dev_iter;

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
    // Correctly iterate through the input_dev list starting from our dummy device
    list_for_each_entry_rcu(dev_iter, &dummy_dev->node, node) {
        if (dev_iter->name && strcmp(dev_iter->name, name) == 0) {
            if (input_get_device(dev_iter)) {
                target_dev = dev_iter;
            }
            break;
        }
    }
    rcu_read_unlock();
    input_unregister_device(dummy_dev);

    if (!target_dev) {
        PRINT_DEBUG("[HIJACK] Device '%s' not found.\n", name);
        mutex_unlock(&hijack_mutex);
        return -ENODEV;
    }

    // 2. Install HOOK 1 on input_event (Snooping Hook)
    input_event_addr_global = (void *)kallsyms_lookup_name("input_event");
    if (!input_event_addr_global) {
        PRINT_DEBUG("[HIJACK] Failed to find address of input_event().\n");
        input_put_device(target_dev);
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }
    if (hook_wrap(input_event_addr_global, 4, hooked_input_event_callback, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[HIJACK] Failed to wrap input_event().\n");
        input_put_device(target_dev);
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }
    PRINT_DEBUG("[HIJACK] HOOK 1 (Snoop) installed on input_event.\n");

    // 3. Install HOOK 2 on evdev_event (Blocking Hook)
    mutex_lock(&target_dev->mutex);
    list_for_each_entry(handle, &target_dev->h_list, d_node) {
        if (handle->handler && handle->handler->name && strcmp(handle->handler->name, "evdev") == 0) {
            evdev_event_addr = handle->handler->event;
            break;
        }
    }
    mutex_unlock(&target_dev->mutex);

    if (!evdev_event_addr) {
        PRINT_DEBUG("[HIJACK] CRITICAL: Could not find evdev_event for '%s'. Unwinding.\n", name);
        hook_unwrap(input_event_addr_global, hooked_input_event_callback, NULL);
        input_put_device(target_dev);
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }
    
    evdev_event_addr_global = evdev_event_addr;
    if (hook_wrap(evdev_event_addr_global, 4, hooked_evdev_event_callback, NULL, NULL) != HOOK_NO_ERR) {
        PRINT_DEBUG("[HIJACK] Failed to wrap evdev_event(). Unwinding.\n");
        hook_unwrap(input_event_addr_global, hooked_input_event_callback, NULL);
        input_put_device(target_dev);
        mutex_unlock(&hijack_mutex);
        return -EFAULT;
    }
    evdev_hook_is_active = true;
    PRINT_DEBUG("[HIJACK] HOOK 2 (Block) installed on evdev_event at %p.\n", evdev_event_addr_global);

    // 4. Finalize state
    hooked_dev = target_dev;
    hook_is_active = true;
    atomic_set(&ring_buffer_head, 0);
    atomic_set(&ring_buffer_tail, 0);
    frame_assembly_buffer.count = 0;

    PRINT_DEBUG("[HIJACK] Successfully established DUAL HOOK on device '%s'.\n", name);
    mutex_unlock(&hijack_mutex);
    return 0;
}

void do_cleanup_hook(void)
{
    mutex_lock(&hijack_mutex);

    if (!hook_is_active) {
        mutex_unlock(&hijack_mutex);
        return;
    }

    // 1. Uninstall HOOK 2 (evdev_event)
    if (evdev_hook_is_active && evdev_event_addr_global) {
        hook_unwrap(evdev_event_addr_global, hooked_evdev_event_callback, NULL);
        PRINT_DEBUG("[HIJACK] Unwrapped evdev_event().\n");
    }
    evdev_hook_is_active = false;
    evdev_event_addr_global = NULL;

    // 2. Uninstall HOOK 1 (input_event)
    if (input_event_addr_global) {
        hook_unwrap(input_event_addr_global, hooked_input_event_callback, NULL);
        PRINT_DEBUG("[HIJACK] Unwrapped input_event().\n");
    }
    input_event_addr_global = NULL;

    // 3. Clear state
    if (hooked_dev) {
        input_put_device(hooked_dev);
        hooked_dev = NULL;
    }
    hook_is_active = false;

    // 4. Wake up any sleeping reader
    wake_up_interruptible(&read_wait_queue);

    PRINT_DEBUG("[HIJACK] All hooks cleaned up.\n");
    mutex_unlock(&hijack_mutex);
}

int do_read_input_events(PEVENT_PACKAGE user_pkg)
{
    int ret, tail;
    unsigned long flags;

    ret = wait_event_interruptible(read_wait_queue, 
                                   atomic_read(&ring_buffer_head) != atomic_read(&ring_buffer_tail) || !hook_is_active);
    if (ret) return -ERESTARTSYS;

    if (!hook_is_active && atomic_read(&ring_buffer_head) == atomic_read(&ring_buffer_tail)) {
        return -ESHUTDOWN;
    }

    spin_lock_irqsave(&ring_buffer_lock, flags);
    tail = atomic_read(&ring_buffer_tail);
    if (tail == atomic_read(&ring_buffer_head)) {
        spin_unlock_irqrestore(&ring_buffer_lock, flags);
        return 0;
    }

    if (copy_to_user(user_pkg, &ring_buffer[tail], sizeof(EVENT_PACKAGE))) {
        spin_unlock_irqrestore(&ring_buffer_lock, flags);
        return -EFAULT;
    }
    
    atomic_set(&ring_buffer_tail, (tail + 1) & (RING_BUFFER_SIZE - 1));
    spin_unlock_irqrestore(&ring_buffer_lock, flags);

    return 0;
}

int do_inject_input_event(struct input_event *event)
{
    struct input_event k_event;
    unsigned long flags;

    if (!hook_is_active || !hooked_dev) return -EINVAL;
    if (copy_from_user(&k_event, event, sizeof(struct input_event))) return -EFAULT;

    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = true;
    spin_unlock_irqrestore(&injection_lock, flags);

    input_event(hooked_dev, k_event.type, k_event.code, k_event.value);

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

    if (!hook_is_active || !hooked_dev) return -EINVAL;
    if (copy_from_user(&k_pkg, user_pkg, sizeof(EVENT_PACKAGE))) return -EFAULT;
    if (k_pkg.count > MAX_EVENTS_PER_READ) return -EINVAL;

    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = true;
    spin_unlock_irqrestore(&injection_lock, flags);

    for (i = 0; i < k_pkg.count; i++) {
        struct input_event *ev = &k_pkg.events[i];
        input_event(hooked_dev, ev->type, ev->code, ev->value);
    }

    spin_lock_irqsave(&injection_lock, flags);
    injection_in_progress = false;
    spin_unlock_irqrestore(&injection_lock, flags);

    return 0;
}

// This function is now obsolete with the dual-hook model, but kept for API compatibility.
// It no longer has any effect.
int do_set_touch_mode(unsigned int mode)
{
    PRINT_DEBUG("[HIJACK] do_set_touch_mode is obsolete with dual-hook and has no effect.\n");
    return 0;
}