#include <linux/input.h>
#include <linux/input/mt.h> // <-- Add this for multi-touch functions
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include "touch.h"
#include "comm.h"
#include "version_control.h"

// --- Struct definitions based on evdev.c ---
// These are needed to correctly interpret file->private_data for event devices.
struct evdev_client;

struct evdev {
	int open;
	struct input_handle handle;
	wait_queue_head_t wait;
	struct evdev_client __rcu *grab;
	struct list_head client_list;
	spinlock_t client_lock; /* protects client_list */
	struct mutex mutex;
	struct device dev;
	struct cdev cdev;
	bool exist;
};

struct evdev_client {
	unsigned int head;
	unsigned int tail;
	unsigned int packet_head;
	spinlock_t buffer_lock;
	struct fasync_struct *fasync;
	struct evdev *evdev;
	struct list_head node;
	unsigned int clk_type;
	bool revoked;
	unsigned long *evmasks[EV_CNT];
	unsigned int bufsize;
	struct input_event buffer[];
};

// --- Global variables ---
static struct input_dev *touch_dev = NULL;
static struct file *touch_filp = NULL; // Keep the file pointer to release it later
static DEFINE_MUTEX(touch_dev_mutex);

// --- RCU-related includes and globals ---
#include <linux/rcupdate.h>
#include <linux/slab.h>

// These are not exported, so we can't use them directly.
// We will find the list via our dummy device.
// extern struct list_head input_dev_list;
// extern struct mutex input_mutex;

// This will be our handle to the hooked device, which we will find.
static struct input_handle *hooked_handle = NULL;


int touch_set_device(const char __user *path) {
    char kpath[64];
    struct evdev_client *client;

    mutex_lock(&touch_dev_mutex);

    if (touch_dev) {
        PRINT_DEBUG("[TOUCH] Device already set. Deinitializing first.\n");
        // Release previous device if any
        if (touch_filp) {
            filp_close(touch_filp, NULL);
            touch_filp = NULL;
        }
        if (touch_dev) {
            input_put_device(touch_dev);
            touch_dev = NULL;
        }
		hooked_handle = NULL;
    }

    if (strncpy_from_user(kpath, path, sizeof(kpath) - 1) < 0) {
        mutex_unlock(&touch_dev_mutex);
        return -EFAULT;
    }
    kpath[sizeof(kpath) - 1] = '\0';

    PRINT_DEBUG("[TOUCH] Opening real touch device: %s\n", kpath);
    touch_filp = filp_open(kpath, O_RDWR, 0);
    if (IS_ERR(touch_filp)) {
        PRINT_DEBUG("[TOUCH] Failed to open %s. Error %ld\n", kpath, PTR_ERR(touch_filp));
        touch_filp = NULL;
        mutex_unlock(&touch_dev_mutex);
        return PTR_ERR(touch_filp);
    }

    client = (struct evdev_client *)touch_filp->private_data;
    if (!client || !client->evdev || !client->evdev->handle.dev) {
        PRINT_DEBUG("[TOUCH] Could not get evdev_client or input_dev from file.\n");
        filp_close(touch_filp, NULL);
        touch_filp = NULL;
        mutex_unlock(&touch_dev_mutex);
        return -EFAULT;
    }

    touch_dev = client->evdev->handle.dev;
    input_get_device(touch_dev); // Increment ref count to hold onto it
	hooked_handle = &client->evdev->handle;

    PRINT_DEBUG("[TOUCH] Successfully hijacked device: %s\n", touch_dev->name);

    mutex_unlock(&touch_dev_mutex);
    return 0;
}

int touch_set_device_by_name(const char *name) {
    struct input_dev *dummy_dev = NULL;
    struct input_dev *target_dev = NULL;
    struct input_handle *target_handle = NULL;
    int ret = 0;

    // --- 1. Create and register a dummy device to get a list anchor ---
    dummy_dev = input_allocate_device();
    if (!dummy_dev) {
        PRINT_DEBUG("[TOUCH_RCU] Failed to allocate dummy device.\n");
        return -ENOMEM;
    }

    dummy_dev->name = "khack_dummy_device";
    ret = input_register_device(dummy_dev);
    if (ret) {
        PRINT_DEBUG("[TOUCH_RCU] Failed to register dummy device.\n");
        input_free_device(dummy_dev);
        return ret;
    }

    // --- 2. Safely traverse the list using RCU read-side protection ---
    PRINT_DEBUG("[TOUCH_RCU] Searching for device: %s\n", name);
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

    // --- 3. Unregister and free the dummy device ---
    input_unregister_device(dummy_dev);
    // Note: input_free_device is called by input_unregister_device's release function.

    // --- 4. Process the found device ---
    if (!target_dev) {
        PRINT_DEBUG("[TOUCH_RCU] Device '%s' not found.\n", name);
        return -ENODEV;
    }

    PRINT_DEBUG("[TOUCH_RCU] Found device: %s. Now finding evdev handle.\n", target_dev->name);

    // Find the 'evdev' handle associated with this device
    struct input_handle *handle;
    list_for_each_entry(handle, &target_dev->h_list, d_node) {
        if (handle->handler && handle->handler->name && strcmp(handle->handler->name, "evdev") == 0) {
            target_handle = handle;
            break;
        }
    }

    if (!target_handle) {
        PRINT_DEBUG("[TOUCH_RCU] Could not find evdev handle for device '%s'.\n", target_dev->name);
        input_put_device(target_dev);
        return -ENODEV;
    }

    // --- 5. Finalize the setup ---
    mutex_lock(&touch_dev_mutex);
    // Clean up any previously set device
    if (touch_dev) {
        input_put_device(touch_dev);
    }
    if (touch_filp) {
        filp_close(touch_filp, NULL);
        touch_filp = NULL;
    }

    // Set the new device and handle
    touch_dev = target_dev; // Already has an incremented ref count from input_get_device
    hooked_handle = target_handle;
    
    mutex_unlock(&touch_dev_mutex);

    PRINT_DEBUG("[TOUCH_RCU] Successfully set device '%s' via RCU traversal.\n", name);

    return 0;
}


void touch_deinit(void) {
    mutex_lock(&touch_dev_mutex);
    if (touch_filp) {
        PRINT_DEBUG("[TOUCH] Closing hijacked device file.\n");
        filp_close(touch_filp, NULL);
        touch_filp = NULL;
    }
    if (touch_dev) {
        PRINT_DEBUG("[TOUCH] Releasing hijacked device handle.\n");
        input_put_device(touch_dev);
        touch_dev = NULL;
    }
	hooked_handle = NULL;
    mutex_unlock(&touch_dev_mutex);
}

void touch_send_event(PTOUCH_DATA data) {
    int i;

    mutex_lock(&touch_dev_mutex);

    if (!touch_dev) {
        mutex_unlock(&touch_dev_mutex);
        return;
    }

    for (i = 0; i < data->point_count; i++) {
        input_mt_slot(touch_dev, data->points[i].id);
        input_mt_report_slot_state(touch_dev, MT_TOOL_FINGER, true);
        input_report_abs(touch_dev, ABS_MT_TRACKING_ID, data->points[i].id);
        input_report_abs(touch_dev, ABS_MT_POSITION_X, data->points[i].x);
        input_report_abs(touch_dev, ABS_MT_POSITION_Y, data->points[i].y);
        if (data->points[i].size1 > 0)
            input_report_abs(touch_dev, ABS_MT_TOUCH_MAJOR, data->points[i].size1);
        if (data->points[i].size2 > 0)
            input_report_abs(touch_dev, ABS_MT_WIDTH_MAJOR, data->points[i].size2);
        if (data->points[i].size3 > 0)
            input_report_abs(touch_dev, ABS_MT_TOUCH_MINOR, data->points[i].size3);
    }

    if (data->point_count == 0) {
        input_mt_sync_frame(touch_dev);
        input_report_key(touch_dev, BTN_TOUCH, 0);
        input_report_key(touch_dev, BTN_TOOL_FINGER, 0);
    } else {
        input_report_key(touch_dev, BTN_TOUCH, 1);
        input_report_key(touch_dev, BTN_TOOL_FINGER, 1);
        input_mt_sync_frame(touch_dev);
    }

    input_sync(touch_dev);
    mutex_unlock(&touch_dev_mutex);
}