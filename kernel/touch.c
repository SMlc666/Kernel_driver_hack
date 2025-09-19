#include <linux/input.h>
#include <linux/input/mt.h> // <-- Add this for multi-touch functions
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "touch.h"
#include "comm.h"

// --- Global variables ---
static struct input_dev *touch_dev = NULL;
static struct file *touch_filp = NULL; // Keep the file pointer to release it later
static DEFINE_MUTEX(touch_dev_mutex);

// NOTE: The struct input_handle is already defined in <linux/input.h> in most modern kernels.
// We removed the local redefinition to avoid compilation errors.

int touch_set_device(const char __user *path) {
    char kpath[64];
    struct input_handle *handle;

    mutex_lock(&touch_dev_mutex);

    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Device already set. Deinitializing first.\n");
        // Release previous device if any
        if (touch_filp) {
            filp_close(touch_filp, NULL);
            touch_filp = NULL;
        }
        if (touch_dev) {
            input_put_device(touch_dev);
            touch_dev = NULL;
        }
    }

    if (strncpy_from_user(kpath, path, sizeof(kpath) - 1) < 0) {
        mutex_unlock(&touch_dev_mutex);
        return -EFAULT;
    }
    kpath[sizeof(kpath) - 1] = '\0';

    printk(KERN_INFO "[TOUCH] Opening real touch device: %s\n", kpath);
    touch_filp = filp_open(kpath, O_RDWR, 0);
    if (IS_ERR(touch_filp)) {
        printk(KERN_ERR "[TOUCH] Failed to open %s. Error %ld\n", kpath, PTR_ERR(touch_filp));
        touch_filp = NULL;
        mutex_unlock(&touch_dev_mutex);
        return PTR_ERR(touch_filp);
    }

    // The input_dev is usually stored in private_data of the file struct,
    // but it's wrapped in an input_handle.
    handle = (struct input_handle *)touch_filp->private_data;
    if (!handle || !handle->dev) {
        printk(KERN_ERR "[TOUCH] Could not get input_handle or input_dev from file.\n");
        filp_close(touch_filp, NULL);
        touch_filp = NULL;
        mutex_unlock(&touch_dev_mutex);
        return -EFAULT;
    }

    touch_dev = handle->dev;
    input_get_device(touch_dev); // Increment ref count to hold onto it

    printk(KERN_INFO "[TOUCH] Successfully hijacked device: %s\n", touch_dev->name);

    mutex_unlock(&touch_dev_mutex);
    return 0;
}

void touch_deinit(void) {
    mutex_lock(&touch_dev_mutex);
    if (touch_filp) {
        printk(KERN_INFO "[TOUCH] Closing hijacked device file.\n");
        filp_close(touch_filp, NULL);
        touch_filp = NULL;
    }
    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Releasing hijacked device handle.\n");
        input_put_device(touch_dev);
        touch_dev = NULL;
    }
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