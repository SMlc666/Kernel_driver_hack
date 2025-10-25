#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/kprobes.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/sched/task.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/major.h>
#include <linux/atomic.h>

#include "touch_input.h"
#include "process.h"
#include "version_control.h"
#include <linux/jiffies.h>

#ifndef MT_TOOL_FINGER
#define MT_TOOL_FINGER 0
#endif

#ifdef CONFIG_TOUCH_INPUT_MODE

// --- Forward Declarations ---
static void unhook_device(void);
static ssize_t hook_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
static unsigned int hook_poll(struct file *file, struct poll_table_struct *wait);
static int install_hook_internal(void);

// --- Global State ---
static struct file *g_target_file = NULL;
static const struct file_operations *g_original_fops;
static struct file_operations g_hooked_fops;
static DEFINE_MUTEX(g_hook_lock);

// Original function pointers
static ssize_t (*g_old_read)(struct file *, char __user *, size_t, loff_t *);
static unsigned int (*g_old_poll)(struct file *, struct poll_table_struct *);

// Pointers to kernel symbols
static struct files_struct *(*get_files_struct_ptr)(struct task_struct *task);
static void (*put_files_struct_ptr)(struct files_struct *files);

// Touch state
#define MAX_SLOTS 10
struct slot_state {
    int tracking_id;
    int x;
    int y;
    bool active;
};
static struct slot_state g_slots[MAX_SLOTS];
static DEFINE_MUTEX(g_slot_lock);

// Evdev client info
static struct evdev_client *g_myclient = NULL;
static struct input_dev *g_real_dev = NULL;

// Module control state
static enum TOUCH_MODE g_current_mode = TOUCH_MODE_DISABLED;

// Active touches counter and tracking id allocator
static int g_active_touches = 0;
static int g_next_tracking_id = 1; // monotonically increasing, avoid -1
static atomic_t g_cleanup_requested = ATOMIC_INIT(0);
static atomic_t g_pending_disable = ATOMIC_INIT(0); // defer disable until cleanup emitted
static atomic_t g_unhooking = ATOMIC_INIT(0); // avoid races in hook_read during unhook

// Synchronous cleanup coordination (for uninstall/disable)
static wait_queue_head_t g_cleanup_wait;
static atomic_t g_cleanup_in_progress = ATOMIC_INIT(0);

// --- Evdev Structures (version dependent) ---
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
struct evdev {
	int open;
	struct input_handle handle;
	struct evdev_client __rcu *grab;
	struct list_head client_list;
	spinlock_t client_lock;
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
	wait_queue_head_t wait;
	struct fasync_struct *fasync;
	struct evdev *evdev;
	struct list_head node;
	bool revoked;
	unsigned long *evmasks[EV_CNT];
	unsigned int bufsize;
	struct input_event buffer[];
};
#else
struct evdev {
	int open;
	struct input_handle handle;
	wait_queue_head_t wait;
	struct evdev_client __rcu *grab;
	struct list_head client_list;
	spinlock_t client_lock;
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
	bool revoked;
	unsigned long *evmasks[EV_CNT];
	unsigned int bufsize;
	struct input_event buffer[];
};
#endif

// --- MMAP Shared Buffer ---
static TOUCH_SHARED_BUFFER *g_shared_buffer = NULL;

// --- Function Implementations ---

int touch_input_init(void)
{
    // Resolve kernel symbols
    get_files_struct_ptr = (void *)kallsyms_lookup_name("get_files_struct");
    put_files_struct_ptr = (void *)kallsyms_lookup_name("put_files_struct");
    if (!get_files_struct_ptr || !put_files_struct_ptr) {
        PRINT_DEBUG("[-] touch_input: Failed to find get_files_struct or put_files_struct\n");
        return -ENOENT;
    }

    // Allocate shared buffer page
    g_shared_buffer = (TOUCH_SHARED_BUFFER *)vmalloc_user(PAGE_ALIGN(sizeof(TOUCH_SHARED_BUFFER)));
    if (!g_shared_buffer) {
        PRINT_DEBUG("[-] touch_input: Failed to allocate shared buffer\n");
        return -ENOMEM;
    }
    
    // Zero out the buffer to ensure physical pages are allocated.
    memset(g_shared_buffer, 0, PAGE_ALIGN(sizeof(TOUCH_SHARED_BUFFER)));
    
    // Initialize buffer state
    g_shared_buffer->head = 0;
    g_shared_buffer->tail = 0;

    // Initialize slot states
    mutex_lock(&g_slot_lock);
    for (int i = 0; i < MAX_SLOTS; ++i) {
        g_slots[i].tracking_id = -1;
        g_slots[i].x = 0;
        g_slots[i].y = 0;
        g_slots[i].active = false;
    }
    g_active_touches = 0;
    g_next_tracking_id = 1;
    mutex_unlock(&g_slot_lock);

    // init cleanup waitqueue
    init_waitqueue_head(&g_cleanup_wait);

    PRINT_DEBUG("[+] touch_input: Module initialized.\n");
    return 0;
}

void touch_input_exit(void)
{
    unhook_device();
    if (g_shared_buffer) {
        vfree(g_shared_buffer);
        g_shared_buffer = NULL;
    }
    PRINT_DEBUG("[+] touch_input: Module exited.\n");
}

long handle_touch_ioctl(unsigned int cmd, unsigned long arg)
{
    // All touch ioctls require the hook to be installed first, except for the install command itself.
    if (cmd != OP_TOUCH_HOOK_INSTALL && !g_target_file) {
        return -ENODEV; // Hook not active
    }

    switch (cmd) {
        case OP_TOUCH_HOOK_INSTALL:
            return install_hook_internal();

        case OP_TOUCH_HOOK_UNINSTALL:
        {
            // Ensure any active touches are fully released before unhooking,
            // so UI state is not left in long-press or stuck gestures.
            int timeout_ok = 1;
            if (g_active_touches > 0) {
                atomic_set(&g_cleanup_requested, 1);
                atomic_set(&g_cleanup_in_progress, 1);
            #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
                if (g_myclient) wake_up_interruptible(&g_myclient->wait);
            #else
                if (g_myclient && g_myclient->evdev) wake_up_interruptible(&g_myclient->evdev->wait);
            #endif
                // wait at most 300ms for cleanup to be emitted and observed
                if (wait_event_interruptible_timeout(g_cleanup_wait,
                        (g_active_touches == 0) || (atomic_read(&g_cleanup_in_progress) == 0),
                        msecs_to_jiffies(300)) <= 0) {
                    // timeout or interrupted: proceed but warn
                    PRINT_DEBUG("[-] touch_input: uninstall cleanup wait timeout/interrupted (active=%d)\n", g_active_touches);
                    timeout_ok = 0;
                }
            }
            unhook_device();
            if (!timeout_ok) {
                // best-effort: nothing else to do, we already unhooked
            }
            return 0;
        }

        case OP_TOUCH_SET_MODE: {
            TOUCH_MODE_CTL ctl;
            if (copy_from_user(&ctl, (void __user *)arg, sizeof(ctl))) {
                return -EFAULT;
            }
            if (ctl.mode >= TOUCH_MODE_DISABLED && ctl.mode <= TOUCH_MODE_EXCLUSIVE_INJECT) {
                // If disabling while there are active touches, defer disable until cleanup is emitted via read
                if (ctl.mode == TOUCH_MODE_DISABLED) {
                    mutex_lock(&g_hook_lock);
                    if (g_current_mode == TOUCH_MODE_EXCLUSIVE_INJECT && g_active_touches > 0) {
                        atomic_set(&g_cleanup_requested, 1);
                        atomic_set(&g_pending_disable, 1);
                        PRINT_DEBUG("[+] touch_input: Defer disable, cleanup requested (active=%d)\n", g_active_touches);
                    #if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
                        if (g_myclient) wake_up_interruptible(&g_myclient->wait);
                    #else
                        if (g_myclient && g_myclient->evdev) wake_up_interruptible(&g_myclient->evdev->wait);
                    #endif
                    } else {
                        g_current_mode = TOUCH_MODE_DISABLED;
                        PRINT_DEBUG("[+] touch_input: Mode set to DISABLED immediately\n");
                    }
                    mutex_unlock(&g_hook_lock);
                    return 0;
                } else {
                    // Switching to EXCLUSIVE_INJECT: 清空底层evdev backlog一次，避免后续“冒出”
                    mutex_lock(&g_hook_lock);
                    g_current_mode = ctl.mode;
                    atomic_set(&g_pending_disable, 0);
                    atomic_set(&g_cleanup_requested, 0);
                    // best-effort flush
                    if (g_myclient) {
                    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
                        spin_lock(&g_myclient->buffer_lock);
                        g_myclient->head = g_myclient->tail;
                        g_myclient->packet_head = g_myclient->tail;
                        spin_unlock(&g_myclient->buffer_lock);
                    #else
                        spin_lock(&g_myclient->buffer_lock);
                        g_myclient->head = g_myclient->tail;
                        g_myclient->packet_head = g_myclient->tail;
                        spin_unlock(&g_myclient->buffer_lock);
                    #endif
                    }
                    mutex_unlock(&g_hook_lock);
                    PRINT_DEBUG("[+] touch_input: Mode set to %d (backlog flushed once)\n", ctl.mode);
                    return 0;
                }
            }
            return -EINVAL;
        }

        case OP_TOUCH_NOTIFY: {
            // This is a signal from userspace that new data is in the ring buffer.
            // We need to wake up the reader (system_server).
            if (g_myclient) {
                #if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
                wake_up_interruptible(&g_myclient->wait);
                #else
                wake_up_interruptible(&g_myclient->evdev->wait);
                #endif
                return 0;
            }
            return -EPIPE;
        }

        case OP_TOUCH_CLEAN_STATE: {
            // Request a full cleanup of all active slots; hook_read will emit releases.
            atomic_set(&g_cleanup_requested, 1);
            // Wake up reader so it can flush immediately
            if (g_myclient) {
            #if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
                wake_up_interruptible(&g_myclient->wait);
            #else
                wake_up_interruptible(&g_myclient->evdev->wait);
            #endif
            }
            PRINT_DEBUG("[+] touch_input: Clean state requested (flag set).\n");
            return 0;
        }
    }
    return -EINVAL;
}

int touch_input_mmap(struct file *filp, struct vm_area_struct *vma)
{
    // Placeholder for mmap logic
    unsigned long size = vma->vm_end - vma->vm_start;
    
    if (size != PAGE_ALIGN(sizeof(TOUCH_SHARED_BUFFER))) {
        return -EINVAL;
    }
    
    if (remap_vmalloc_range(vma, g_shared_buffer, 0)) {
        PRINT_DEBUG("[-] touch_input: remap_vmalloc_range failed\n");
        return -EAGAIN;
    }
    
    PRINT_DEBUG("[+] touch_input: Shared buffer mmapped successfully.\n");
    return 0;
}

// --- Internal Helper Functions ---

// Find the evdev struct from an input_dev using a hybrid approach
static struct evdev *input_dev_to_evdev(struct input_dev *dev) {
    struct input_handle *handle;
    struct evdev *evdev = NULL;
    static struct input_handler *evdev_handler_ptr = NULL;
    static bool kallsyms_failed = false;

    if (!dev) return NULL;

    // Strategy: Prioritize kallsyms, fallback to name comparison.
    if (!kallsyms_failed && !evdev_handler_ptr) {
        evdev_handler_ptr = (struct input_handler *)kallsyms_lookup_name("evdev_handler");
        if (!evdev_handler_ptr) {
            PRINT_DEBUG("[!] touch_input: kallsyms failed for evdev_handler, falling back to name search.\n");
            kallsyms_failed = true;
        }
    }

    mutex_lock(&dev->mutex);
    list_for_each_entry(handle, &dev->h_list, d_node) {
        if (evdev_handler_ptr) {
            // Fast path: kallsyms worked
            if (handle->handler == evdev_handler_ptr) {
                evdev = handle->private;
                break;
            }
        } else {
            // Fallback path: kallsyms failed, compare by name
            if (handle->handler && handle->handler->name && strcmp(handle->handler->name, "evdev") == 0) {
                evdev = handle->private;
                break;
            }
        }
    }
    mutex_unlock(&dev->mutex);

    if (!evdev) {
        PRINT_DEBUG("[-] touch_input: Failed to find evdev handler for device %s\n", dev->name);
    }

    return evdev;
}

// Find the primary touch device using a hybrid approach
static struct input_dev* find_touch_device(void) {
    static struct input_dev* CACHE = NULL;
    struct input_dev *dev = NULL;
    static struct list_head *input_dev_list = NULL;
    static struct mutex *input_mutex = NULL;
    static bool kallsyms_failed = false;
    struct input_dev *dummy_dev;
    struct list_head *p;
    struct input_dev *iter_dev;

    if (CACHE != NULL) return CACHE;

    // Strategy: Prioritize kallsyms, fallback to dummy device method.
    if (!kallsyms_failed && (!input_dev_list || !input_mutex)) {
        input_dev_list = (struct list_head *)kallsyms_lookup_name("input_dev_list");
        input_mutex = (struct mutex *)kallsyms_lookup_name("input_mutex");
        if (!input_dev_list || !input_mutex) {
            PRINT_DEBUG("[!] touch_input: kallsyms failed for input_dev_list/input_mutex, falling back to dummy device method.\n");
            kallsyms_failed = true;
        }
    }

    if (input_dev_list && input_mutex) {
        // Fast path: kallsyms worked
        mutex_lock(input_mutex);
        list_for_each_entry(dev, input_dev_list, node) {
            if (test_bit(EV_ABS, dev->evbit) && test_bit(ABS_MT_POSITION_X, dev->absbit)) {
                PRINT_DEBUG("[+] touch_input: Found touch device (via kallsyms): %s\n", dev->name);
                CACHE = dev;
                break;
            }
        }
        mutex_unlock(input_mutex);
        return CACHE;
    } else {
        // Fallback path: kallsyms failed, use dummy device
        dummy_dev = input_allocate_device();
        if (!dummy_dev) {
            PRINT_DEBUG("[-] touch_input: Failed to allocate dummy device for fallback search\n");
            return NULL;
        }
        dummy_dev->name = "khack_touch_finder";
        if (input_register_device(dummy_dev) != 0) {
            input_free_device(dummy_dev);
            return NULL;
        }

        rcu_read_lock();
        for (p = dummy_dev->node.next; p != &dummy_dev->node; p = p->next) {
            iter_dev = container_of(p, struct input_dev, node);
            if (test_bit(EV_ABS, iter_dev->evbit) && test_bit(ABS_MT_POSITION_X, iter_dev->absbit)) {
                PRINT_DEBUG("[+] touch_input: Found touch device (via fallback): %s\n", iter_dev->name);
                dev = iter_dev;
                break;
            }
        }
        rcu_read_unlock();

        input_unregister_device(dummy_dev);
        input_free_device(dummy_dev);

        if (dev) {
            CACHE = dev;
        }
        return dev;
    }
}

// Get the event index (e.g., 4 for /dev/input/event4)
static int get_touch_event_index(void) {
    struct input_dev *touch_dev = find_touch_device();
    struct evdev *evdev;
    if (!touch_dev) return -ENODEV;
    evdev = input_dev_to_evdev(touch_dev);
    if (!evdev) return -EFAULT;
    return MINOR(evdev->cdev.dev) - 64;
}

// Find a file descriptor in a process by its device number
__attribute__((no_sanitize("cfi")))
static int find_fd_by_devt_in_proc(pid_t pid, dev_t target_dev)
{
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdt;
	int fd = -ENOENT;
	unsigned int i;

	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task) {
		return -ESRCH;
	}

	files = get_files_struct_ptr(task);
	put_task_struct(task);
	if (!files) {
		return -ENOENT;
	}

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	for (i = 0; i < fdt->max_fds; i++) {
		struct file *f = fdt->fd[i];
		if (f) {
			struct inode *inode = file_inode(f);
			if (inode && S_ISCHR(inode->i_mode) && inode->i_rdev == target_dev) {
				fd = i;
				break;
			}
		}
	}
	spin_unlock(&files->file_lock);
	
	put_files_struct_ptr(files);

	return fd;
}

// Get a file struct from a task by its fd
static struct file *my_fget_task(struct task_struct *task, unsigned int fd)
{
    struct file *file = NULL;
    struct files_struct *files;
    struct fdtable *fdt;

    files = get_files_struct_ptr(task);
    if (!files) {
        return NULL;
    }

    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (fd < fdt->max_fds) {
        file = fdt->fd[fd];
        if (file) {
            get_file(file);
        }
    }
    spin_unlock(&files->file_lock);

    put_files_struct_ptr(files);

    return file;
}

// Hook the file operations of the target file
static int hook_fops(int pid, int fd) {
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return -ESRCH;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return -ESRCH;

    g_target_file = my_fget_task(task, fd);
    put_task_struct(task);
    if (!g_target_file) return -EBADF;

    g_myclient = g_target_file->private_data;
    if (!g_myclient || !g_myclient->evdev || !g_myclient->evdev->handle.dev) {
        fput(g_target_file); g_target_file = NULL;
        return -EINVAL;
    }
    g_real_dev = g_myclient->evdev->handle.dev;

    g_original_fops = g_target_file->f_op;
    memcpy(&g_hooked_fops, g_original_fops, sizeof(struct file_operations));
    g_old_read = g_original_fops->read;
    g_old_poll = g_original_fops->poll;
    g_hooked_fops.read = hook_read;
    g_hooked_fops.poll = hook_poll;
    g_target_file->f_op = &g_hooked_fops;

    PRINT_DEBUG("[+] touch_input: Successfully hooked pid: %d, fd: %d\n", pid, fd);
    return 0;
}

static void unhook_device(void)
{
    mutex_lock(&g_hook_lock);
    atomic_set(&g_unhooking, 1);
    if (g_target_file && g_original_fops) {
        // best-effort: reset internal slots and drop any pending evdev client backlog
        mutex_lock(&g_slot_lock);
        for (int i = 0; i < MAX_SLOTS; ++i) {
            g_slots[i].active = false;
            g_slots[i].tracking_id = -1;
            g_slots[i].x = g_slots[i].y = 0;
        }
        g_active_touches = 0;
        mutex_unlock(&g_slot_lock);

        /* do not flush evdev client backlog on unhook: preserve reader state */

        g_target_file->f_op = g_original_fops;
        fput(g_target_file);
        g_target_file = NULL;
        g_original_fops = NULL;
        g_myclient = NULL;
        g_real_dev = NULL;
        g_current_mode = TOUCH_MODE_DISABLED;
        PRINT_DEBUG("[+] touch_input: Unhooked input device (state reset).\n");
    }
    atomic_set(&g_unhooking, 0);
    mutex_unlock(&g_hook_lock);
}

static int install_hook_internal(void)
{
    pid_t sys_server_pid;
    int event_idx, fd, result;
    dev_t touch_dev_t;

    mutex_lock(&g_hook_lock);
    if (g_target_file) {
        mutex_unlock(&g_hook_lock);
        PRINT_DEBUG("[-] touch_input: Input is already hooked\n");
        return -EBUSY;
    }

    event_idx = get_touch_event_index();
    if (event_idx < 0) {
        PRINT_DEBUG("[-] touch_input: Failed to find event_idx: %d\n", event_idx);
        mutex_unlock(&g_hook_lock);
        return event_idx;
    }
    PRINT_DEBUG("[+] touch_input: Target input_event: /dev/input/event%d\n", event_idx);

    sys_server_pid = get_process_pid("system_server");
    if (sys_server_pid <= 0) {
        PRINT_DEBUG("[-] touch_input: Failed to find system_server: %d\n", sys_server_pid);
        mutex_unlock(&g_hook_lock);
        return -ESRCH;
    }
    PRINT_DEBUG("[+] touch_input: Found system_server PID: %d\n", sys_server_pid);

    touch_dev_t = MKDEV(INPUT_MAJOR, 64 + event_idx);
    fd = find_fd_by_devt_in_proc(sys_server_pid, touch_dev_t);

    if (fd < 0) {
        PRINT_DEBUG("[-] touch_input: system_server failed to find event%d's fd: %d\n", event_idx, fd);
        mutex_unlock(&g_hook_lock);
        return fd;
    }

    result = hook_fops(sys_server_pid, fd);
    if (result == 0) {
        g_current_mode = TOUCH_MODE_DISABLED; // Hooked but inactive by default
    }
    mutex_unlock(&g_hook_lock);

    return result;
}

#define MAX_INJECT_EVENTS 256
static struct input_event g_inject_events[MAX_INJECT_EVENTS];
static unsigned int g_inject_count = 0;

// Helper to build an input_event and add it to our buffer
static void append_event(u16 type, u16 code, s32 value) {
    struct input_event *evt;
    struct timespec64 ts;

    if (g_inject_count >= MAX_INJECT_EVENTS) return;
    evt = &g_inject_events[g_inject_count];
    
    // Get timestamp for the event
    ktime_get_real_ts64(&ts);
    evt->time.tv_sec = ts.tv_sec;
    evt->time.tv_usec = ts.tv_nsec / 1000;

    evt->type = type;
    evt->code = code;
    evt->value = value;
    g_inject_count++;
}

// Helpers
static inline int clampi(int v, int lo, int hi) {
    if (hi < lo) return v;
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static inline void get_abs_bounds(struct input_dev *dev, int code, int *minv, int *maxv) {
    int min_default = 0, max_default = 4095;
    if (!dev || !test_bit(code, dev->absbit) || !dev->absinfo) {
        *minv = min_default; *maxv = max_default; return;
    }
    *minv = dev->absinfo[code].minimum;
    *maxv = dev->absinfo[code].maximum;
    if (*maxv <= *minv) { *minv = min_default; *maxv = max_default; }
}

static inline bool has_abs(struct input_dev *dev, int code) {
    return dev && test_bit(code, dev->absbit);
}

// Map user-space input coord to device coord:
// - If device max > 1000 and incoming v is within [0,1000], treat it as normalized 0..1000 and scale.
// - Otherwise clamp to device bounds.
static inline int map_coord_input_to_device(int v, int minv, int maxv) {
    if (maxv > 1000 && v >= 0 && v <= 1000) {
        // scale linearly, avoid overflow
        int span = maxv - minv;
        int scaled = minv + (v * span) / 1000;
        // clamp in case of rounding
        return clampi(scaled, minv, maxv);
    }
    return clampi(v, minv, maxv);
}

static inline void evdev_flush_client_buffer(struct evdev_client *client) {
    if (!client) return;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
    spin_lock(&client->buffer_lock);
    client->head = client->tail;
    client->packet_head = client->tail;
    spin_unlock(&client->buffer_lock);
#else
    spin_lock(&client->buffer_lock);
    client->head = client->tail;
    client->packet_head = client->tail;
    spin_unlock(&client->buffer_lock);
#endif
}

static ssize_t hook_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    enum TOUCH_MODE current_mode;
    TOUCH_POINT point;
    struct slot_state *s;
    size_t bytes_to_copy;

    // Read current mode
    mutex_lock(&g_hook_lock);
    current_mode = g_current_mode;
    mutex_unlock(&g_hook_lock);

    // If unhooking in progress, fail-safe: pass-through to original
    if (atomic_read(&g_unhooking)) {
        return g_old_read(file, buf, count, pos);
    }

    // Snapshot client/dev pointers to avoid TOCTOU with unhook/disable
    struct evdev_client *client = READ_ONCE(g_myclient);
    struct input_dev *dev_local = READ_ONCE(g_real_dev);

    // Pass-through when disabled or filter mode
    if (current_mode == TOUCH_MODE_DISABLED) {
        return g_old_read(file, buf, count, pos);
    }
    if (current_mode == TOUCH_MODE_FILTER_MODIFY) {
        return g_old_read(file, buf, count, pos);
    }

    // Defensive: if unhook/uninstall raced and internal pointers are gone, pass-through to original
    if (!client || !dev_local) {
        return g_old_read(file, buf, count, pos);
    }

    // Exclusive inject mode
    if (current_mode == TOUCH_MODE_EXCLUSIVE_INJECT) {
        int xmin, xmax, ymin, ymax;

        if (!g_shared_buffer) return -EIO;

        /* preserve client state; do not flush evdev backlog here */
        (void)client;

        // If ring buffer currently empty, emulate evdev blocking read semantics (无超时，避免UI空转)
        if (g_shared_buffer->head == g_shared_buffer->tail && atomic_read(&g_cleanup_requested) == 0) {
            // 防御：在等待前检查 client/dev 指针，避免卸载/切换模式期间 NULL 访问
            if (!client || !dev_local
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0))
                || !client->evdev
#endif
            ) {
                return -EAGAIN;
            }
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
            {
                int retw = wait_event_interruptible(
                    client->wait,
                    (g_shared_buffer->head != g_shared_buffer->tail) || atomic_read(&g_cleanup_requested)
                );
                if (retw < 0) {
                    return -ERESTARTSYS;
                }
            } else {
                // No wait queue available; degrade to EAGAIN
                return -EAGAIN;
            }
#else
            {
                int retw = wait_event_interruptible(
                    client->evdev->wait,
                    (g_shared_buffer->head != g_shared_buffer->tail) || atomic_read(&g_cleanup_requested)
                );
                if (retw < 0) return -ERESTARTSYS;
            }
#endif
        }

        // Build injection
        mutex_lock(&g_slot_lock);
        g_inject_count = 0;

        // Bounds for clamping
        if (!dev_local) { mutex_unlock(&g_slot_lock); return -EAGAIN; }
        get_abs_bounds(dev_local, ABS_MT_POSITION_X, &xmin, &xmax);
        get_abs_bounds(dev_local, ABS_MT_POSITION_Y, &ymin, &ymax);

        // Handle cleanup request first: release all active slots
        if (atomic_xchg(&g_cleanup_requested, 0) == 1) {
            bool any_release = false;
            for (int i = 0; i < MAX_SLOTS && g_inject_count < MAX_INJECT_EVENTS - 4; ++i) {
                struct slot_state *st = &g_slots[i];
                if (st->active) {
                    append_event(EV_ABS, ABS_MT_SLOT, i);
                    append_event(EV_ABS, ABS_MT_TRACKING_ID, -1);
                    st->active = false;
                    st->tracking_id = -1;
                    any_release = true;
                }
            }
            if (any_release) {
                g_active_touches = 0;
                append_event(EV_KEY, BTN_TOOL_FINGER, 0);
                append_event(EV_KEY, BTN_TOUCH, 0);
                append_event(EV_SYN, SYN_REPORT, 0);
                bytes_to_copy = g_inject_count * sizeof(struct input_event);
                if (bytes_to_copy > count) bytes_to_copy = count - (count % sizeof(struct input_event));
                if (copy_to_user(buf, g_inject_events, bytes_to_copy)) {
                    mutex_unlock(&g_slot_lock);
                    return -EFAULT;
                }
                mutex_unlock(&g_slot_lock);

                // signal cleanup completion to any waiter (e.g., uninstall)
                atomic_set(&g_cleanup_in_progress, 0);
                wake_up_all(&g_cleanup_wait);

                /* finalize deferred disable after cleanup */
                if (atomic_read(&g_pending_disable) == 1 && g_active_touches == 0) {
                    if (g_shared_buffer->head == g_shared_buffer->tail) {
                        mutex_lock(&g_hook_lock);
                        g_current_mode = TOUCH_MODE_DISABLED;
                        mutex_unlock(&g_hook_lock);
                        atomic_set(&g_pending_disable, 0);
                        PRINT_DEBUG("[+] touch_input: Cleanup-only frame sent, switched to DISABLED\n");
                    }
                }

                return bytes_to_copy;
            }
            g_inject_count = 0;
        }

        // If still no data after possible wake, report no data
        if (g_shared_buffer->head == g_shared_buffer->tail) {
            mutex_unlock(&g_slot_lock);
            return -EAGAIN;
        }

        // Process only one point per read to improve pacing and avoid UI long-press/latency
        if (g_shared_buffer->head != g_shared_buffer->tail) {
            point = g_shared_buffer->points[g_shared_buffer->tail];
            g_shared_buffer->tail = (g_shared_buffer->tail + 1) % TOUCH_BUFFER_POINTS;

            if (point.slot >= MAX_SLOTS) {
                continue;
            }

            s = &g_slots[point.slot];

            if (point.action == TOUCH_ACTION_MOVE && !s->active) {
                point.action = TOUCH_ACTION_DOWN;
            }

            PRINT_DEBUG("[touch_input] pt: slot=%u action=%d x=%d y=%d active_touches=%d\n",
                        point.slot, point.action, point.x, point.y, g_active_touches);

            switch (point.action) {
                case TOUCH_ACTION_DOWN: {
                    bool need_keys_down = (g_active_touches == 0);

                    if (!s->active) {
                        s->active = true;
                        if (g_next_tracking_id == -1) g_next_tracking_id = 1;
                        s->tracking_id = g_next_tracking_id++;
                        if (g_next_tracking_id <= 0) g_next_tracking_id = 1;
                        g_active_touches++;
                    }
                    s->x = map_coord_input_to_device(point.x, xmin, xmax);
                    s->y = map_coord_input_to_device(point.y, ymin, ymax);

                    append_event(EV_ABS, ABS_MT_SLOT, point.slot);
                    append_event(EV_ABS, ABS_MT_TRACKING_ID, s->tracking_id);
                    append_event(EV_ABS, ABS_MT_POSITION_X, s->x);
                    append_event(EV_ABS, ABS_MT_POSITION_Y, s->y);
                    /* Mirror to single-touch axes if present to help UI consumers */
                    if (has_abs(dev_local, ABS_X)) {
                        append_event(EV_ABS, ABS_X, s->x);
                    }
                    if (has_abs(dev_local, ABS_Y)) {
                        append_event(EV_ABS, ABS_Y, s->y);
                    }
                    
                    if (need_keys_down) {
                        append_event(EV_KEY, BTN_TOOL_FINGER, 1);
                        append_event(EV_KEY, BTN_TOUCH, 1);
                    }
                    break;
                }
                case TOUCH_ACTION_MOVE: {
                    if (s->active) {
                        int nx = map_coord_input_to_device(point.x, xmin, xmax);
                        int ny = map_coord_input_to_device(point.y, ymin, ymax);
                        s->x = nx; s->y = ny;
                        append_event(EV_ABS, ABS_MT_SLOT, point.slot);
                        append_event(EV_ABS, ABS_MT_POSITION_X, s->x);
                        append_event(EV_ABS, ABS_MT_POSITION_Y, s->y);
                        // Mirror to single-touch axes if present to help UI consumers
                        if (has_abs(dev_local, ABS_X)) {
                            append_event(EV_ABS, ABS_X, s->x);
                        }
                        if (has_abs(dev_local, ABS_Y)) {
                            append_event(EV_ABS, ABS_Y, s->y);
                        }
                    }
                    break;
                }
                case TOUCH_ACTION_UP: {
                    if (s->active) {
                        append_event(EV_ABS, ABS_MT_SLOT, point.slot);
                        append_event(EV_ABS, ABS_MT_TRACKING_ID, -1);
                        s->active = false;
                        s->tracking_id = -1;
                        if (g_active_touches > 0) g_active_touches--;
                        if (g_active_touches == 0) {
                            append_event(EV_KEY, BTN_TOOL_FINGER, 0);
                            append_event(EV_KEY, BTN_TOUCH, 0);
                        }
                    }
                    break;
                }
                default:
                    break;
            }
        }

        // Final SYN_REPORT
        if (g_inject_count > 0) {
            append_event(EV_SYN, SYN_REPORT, 0);

            bytes_to_copy = g_inject_count * sizeof(struct input_event);
            if (bytes_to_copy > count) {
                bytes_to_copy = count - (count % sizeof(struct input_event));
            }

            if (copy_to_user(buf, g_inject_events, bytes_to_copy)) {
                mutex_unlock(&g_slot_lock);
                return -EFAULT;
            }
            mutex_unlock(&g_slot_lock);

            /* finalize deferred disable if requested and没有活跃触点 */
            if (atomic_read(&g_pending_disable) == 1 && g_active_touches == 0) {
                if (g_shared_buffer->head == g_shared_buffer->tail) {
                    mutex_lock(&g_hook_lock);
                    g_current_mode = TOUCH_MODE_DISABLED;
                    mutex_unlock(&g_hook_lock);
                    atomic_set(&g_pending_disable, 0);
                    PRINT_DEBUG("[+] touch_input: Pending disable applied after frame\n");
                }
            }

            // signal cleanup completion (no active touches)
            if (g_active_touches == 0) {
                atomic_set(&g_cleanup_in_progress, 0);
                wake_up_all(&g_cleanup_wait);
            }

            return bytes_to_copy;
        }

        mutex_unlock(&g_slot_lock);

        /* 模拟 evdev 语义：阻塞/非阻塞 */
        if (file->f_flags & O_NONBLOCK) {
            return -EAGAIN;
        }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0))
        if (g_myclient) {
            long waited = wait_event_interruptible_timeout(
                g_myclient->wait,
                (g_shared_buffer->head != g_shared_buffer->tail) || atomic_read(&g_cleanup_requested),
                msecs_to_jiffies(100)
            );
            if (waited == 0) return -EAGAIN;
            if (waited < 0) return -ERESTARTSYS;
            /* retry to build frame */
            return hook_read(file, buf, count, pos);
        }
#else
        if (g_myclient && g_myclient->evdev) {
            long waited = wait_event_interruptible_timeout(
                g_myclient->evdev->wait,
                (g_shared_buffer->head != g_shared_buffer->tail) || atomic_read(&g_cleanup_requested),
                msecs_to_jiffies(100)
            );
            if (waited == 0) return -EAGAIN;
            if (waited < 0) return -ERESTARTSYS;
            return hook_read(file, buf, count, pos);
        }
#endif
        return -EAGAIN;
    }

    // Fallback
    return g_old_read(file, buf, count, pos);
}

static unsigned int hook_poll(struct file *file, struct poll_table_struct *wait)
{
    unsigned int mask = g_old_poll(file, wait);
    
    // If we are in injection mode and our buffer has data, signal it
    if (g_current_mode == TOUCH_MODE_EXCLUSIVE_INJECT && g_shared_buffer) {
        if (g_shared_buffer->head != g_shared_buffer->tail) {
            mask |= POLLIN | POLLRDNORM;
        }
    }

    return mask;
}
#endif
