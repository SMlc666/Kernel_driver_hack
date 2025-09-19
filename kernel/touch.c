#include <linux/input.h>
#include <linux/module.h>
#include <linux/input/mt.h>
#include "touch.h"
#include "comm.h"

static struct input_dev *touch_dev = NULL;
static DEFINE_MUTEX(touch_dev_mutex);

// Helper to check if a bit is set
static inline bool is_bit_set(const unsigned long *arr, int bit) {
    return test_bit(bit, arr);
}

int touch_init(PTOUCH_INIT_DATA data) {
    struct input_dev *dev;

    mutex_lock(&touch_dev_mutex);

    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Already initialized.\n");
        mutex_unlock(&touch_dev_mutex);
        return 0;
    }

    printk(KERN_INFO "[TOUCH] Searching for touch screen device...\n");

    rcu_read_lock();
    for_each_input_dev(dev) {
        if (is_bit_set(dev->evbit, EV_ABS) &&
            is_bit_set(dev->absbit, ABS_MT_POSITION_X) &&
            is_bit_set(dev->absbit, ABS_MT_POSITION_Y) &&
            is_bit_set(dev->keybit, BTN_TOUCH)) {
            
            if (strnstr(dev->name, "touch", sizeof(dev->name)) || strnstr(dev->name, "screen", sizeof(dev->name))) {
                printk(KERN_INFO "[TOUCH] Found potential device: %s (%s)\n", dev->name, dev->phys);
                touch_dev = input_get_device(dev);
                break;
            }
        }
    }
    rcu_read_unlock();

    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Successfully selected device: %s\n", touch_dev->name);
        mutex_unlock(&touch_dev_mutex);
        return 0;
    }

    mutex_unlock(&touch_dev_mutex);
    printk(KERN_ERR "[TOUCH] Failed to find a suitable touch screen device.\n");
    return -ENODEV;
}

void touch_deinit(void) {
    mutex_lock(&touch_dev_mutex);
    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Deinitializing touch device.\n");
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
