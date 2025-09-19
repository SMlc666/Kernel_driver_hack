#include <linux/input.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/input/mt.h>
#include "touch.h"
#include "comm.h"

// We need to define the uinput structure ourselves as we are in kernel space.
// This is a stable ABI, so it's safe to do.
#define UINPUT_MAX_NAME_SIZE    80
struct uinput_user_dev {
    char name[UINPUT_MAX_NAME_SIZE];
    struct input_id id;
    __u32 ff_effects_max;
    __s32 absmax[ABS_MAX + 1];
    __s32 absmin[ABS_MAX + 1];
    __s32 absfuzz[ABS_MAX + 1];
    __s32 absflat[ABS_MAX + 1];
};

// ioctl commands for uinput
#define UINPUT_IOCTL_BASE 'U'
#define UI_DEV_CREATE  _IO(UINPUT_IOCTL_BASE, 1)
#define UI_DEV_DESTROY _IO(UINPUT_IOCTL_BASE, 2)
#define UI_SET_EVBIT   _IOW(UINPUT_IOCTL_BASE, 100, int)
#define UI_SET_KEYBIT  _IOW(UINPUT_IOCTL_BASE, 101, int)
#define UI_SET_ABSBIT  _IOW(UINPUT_IOCTL_BASE, 103, int)


// --- Our global variables ---
static struct input_dev *touch_dev = NULL;
static DEFINE_MUTEX(touch_dev_mutex);

// Forward declaration
long uinput_ioctl(struct file *file, unsigned int cmd, unsigned long arg);


int touch_init(PTOUCH_INIT_DATA data) {
    struct file *filp;
    struct uinput_user_dev uidev;
    long ret;
    void *private_data_ptr;

    mutex_lock(&touch_dev_mutex);

    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Already initialized.\n");
        mutex_unlock(&touch_dev_mutex);
        return 0;
    }

    printk(KERN_INFO "[TOUCH] Creating temporary uinput device to get handle...\n");

    filp = filp_open("/dev/uinput", O_WRONLY | O_NONBLOCK, 0);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "[TOUCH] Failed to open /dev/uinput. Error %ld\n", PTR_ERR(filp));
        mutex_unlock(&touch_dev_mutex);
        return PTR_ERR(filp);
    }

    memset(&uidev, 0, sizeof(uidev));
    snprintf(uidev.name, UINPUT_MAX_NAME_SIZE, "internal-touch-handle");
    uidev.id.bustype = BUS_VIRTUAL;
    uidev.id.vendor  = 0x1234;
    uidev.id.product = 0x5678;
    uidev.id.version = 1;

    // Setup capabilities
    uinput_ioctl(filp, UI_SET_EVBIT, EV_KEY);
    uinput_ioctl(filp, UI_SET_KEYBIT, BTN_TOUCH);
    uinput_ioctl(filp, UI_SET_KEYBIT, BTN_TOOL_FINGER);
    
    uinput_ioctl(filp, UI_SET_EVBIT, EV_ABS);
    uinput_ioctl(filp, UI_SET_ABSBIT, ABS_MT_POSITION_X);
    uinput_ioctl(filp, UI_SET_ABSBIT, ABS_MT_POSITION_Y);
    uinput_ioctl(filp, UI_SET_ABSBIT, ABS_MT_TRACKING_ID);
    uinput_ioctl(filp, UI_SET_ABSBIT, ABS_MT_TOUCH_MAJOR);
    uinput_ioctl(filp, UI_SET_ABSBIT, ABS_MT_WIDTH_MAJOR);
    uinput_ioctl(filp, UI_SET_ABSBIT, ABS_MT_TOUCH_MINOR);

    uidev.absmin[ABS_MT_POSITION_X] = 0;
    uidev.absmax[ABS_MT_POSITION_X] = data->max_x > 0 ? data->max_x : 1080;
    uidev.absmin[ABS_MT_POSITION_Y] = 0;
    uidev.absmax[ABS_MT_POSITION_Y] = data->max_y > 0 ? data->max_y : 1920;
    uidev.absmin[ABS_MT_TRACKING_ID] = 0;
    uidev.absmax[ABS_MT_TRACKING_ID] = 65535;
    uidev.absmin[ABS_MT_TOUCH_MAJOR] = 0;
    uidev.absmax[ABS_MT_TOUCH_MAJOR] = 255;
    uidev.absmin[ABS_MT_WIDTH_MAJOR] = 0;
    uidev.absmax[ABS_MT_WIDTH_MAJOR] = 255;
    uidev.absmin[ABS_MT_TOUCH_MINOR] = 0;
    uidev.absmax[ABS_MT_TOUCH_MINOR] = 255;

    ret = kernel_write(filp, (char *)&uidev, sizeof(uidev), &filp->f_pos);
    if (ret != sizeof(uidev)) {
        printk(KERN_ERR "[TOUCH] Failed to write to uinput device. Error %ld\n", ret);
        goto fail;
    }

    ret = uinput_ioctl(filp, UI_DEV_CREATE, 0);
    if (ret < 0) {
        printk(KERN_ERR "[TOUCH] Failed to create uinput device. Error %ld\n", ret);
        goto fail;
    }

    // --- The most important part ---
    // The uinput driver stores the created input_dev in private_data.
    // We need to know the internal structure of uinput_cdev_struct to get it.
    // struct uinput_cdev_struct { struct input_dev *dev; ... };
    // So, private_data is a pointer to this struct. We can dereference it once.
    private_data_ptr = filp->private_data;
    if (!private_data_ptr) {
         printk(KERN_ERR "[TOUCH] uinput private_data is NULL.\n");
         goto fail;
    }
    touch_dev = *(struct input_dev **)private_data_ptr;
    if (!touch_dev) {
        printk(KERN_ERR "[TOUCH] Failed to get input_dev from uinput private_data.\n");
        goto fail;
    }
    
    // We got the handle, now increment its ref count so it stays even after we destroy the uinput device
    input_get_device(touch_dev);
    printk(KERN_INFO "[TOUCH] Successfully acquired handle to virtual device: %s\n", touch_dev->name);

    // Destroy the temporary uinput device immediately
    uinput_ioctl(filp, UI_DEV_DESTROY, 0);
    filp_close(filp, NULL);

    mutex_unlock(&touch_dev_mutex);
    return 0;

fail:
    filp_close(filp, NULL);
    mutex_unlock(&touch_dev_mutex);
    return -EFAULT;
}

void touch_deinit(void) {
    mutex_lock(&touch_dev_mutex);
    if (touch_dev) {
        printk(KERN_INFO "[TOUCH] Deinitializing and releasing touch device handle.\n");
        input_put_device(touch_dev); // This will now properly release the device
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

// Helper to call the ioctl method of the uinput file operations
long uinput_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = -ENOTTY;
    if (file->f_op && file->f_op->unlocked_ioctl) {
        ret = file->f_op->unlocked_ioctl(file, cmd, arg);
    }
    return ret;
}