/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * touch_injector.c
 * 真实设备注入 + 核心层最小钩子：
 * - 保持 deviceId 不变
 * - EXCLUSIVE 模式严格独占：源头丢弃真实触摸事件，仅注入合成帧
 * - 不新增设备，不动 read/poll
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/kallsyms.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/version.h>

#include "comm.h"
#include "touch_injector.h"
#include "inline_hook/p_hook.h"

/* 从 touch_input.c 暴露的共享缓冲访问器 */
extern TOUCH_SHARED_BUFFER *touch_get_shared_buffer(void);

/* 原始 input_event 函数指针与替换 */
static void (*orig_input_event)(struct input_dev *dev, unsigned int type, unsigned int code, int value) = NULL;
static void (*k_input_event)(struct input_dev *dev, unsigned int type, unsigned int code, int value) = NULL;

/* 注入全局状态 */
static struct input_dev *g_target_dev = NULL;
static atomic_t g_inject_enabled = ATOMIC_INIT(0);
static atomic_t g_inject_in_progress = ATOMIC_INIT(0); /* 递归保护：我们自己的注入应透传到 orig_input_event */

static wait_queue_head_t g_inject_wait;
static struct task_struct *g_inject_thread = NULL;

/* 本地 slot 状态（与 touch_input.c 的 g_slots 独立） */
#define INJ_MAX_SLOTS 10
struct inj_slot_state {
    int tracking_id;
    int x;
    int y;
    bool active;
};
static struct inj_slot_state g_inj_slots[INJ_MAX_SLOTS];
static int g_inj_active_touches = 0;
static int g_inj_next_tracking_id = 1;

static DEFINE_MUTEX(g_inject_lock); /* 保护 enable/disable 与设备指针 */

/* 工具函数（复制 touch_input.c 的逻辑以避免跨文件静态函数依赖） */
static inline int clampi(int v, int lo, int hi) {
    if (hi < lo) return v;
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
static inline void get_abs_bounds_local(struct input_dev *dev, int code, int *minv, int *maxv) {
    int min_default = 0, max_default = 4095;
    if (!dev || !test_bit(code, dev->absbit) || !dev->absinfo) {
        *minv = min_default; *maxv = max_default; return;
    }
    *minv = dev->absinfo[code].minimum;
    *maxv = dev->absinfo[code].maximum;
    if (*maxv <= *minv) { *minv = min_default; *maxv = max_default; }
}
static inline bool has_abs_local(struct input_dev *dev, int code) {
    return dev && test_bit(code, dev->absbit);
}
static inline bool has_key_local(struct input_dev *dev, int code) {
    return dev && test_bit(code, dev->keybit);
}
/* 输入映射：如果设备 max>1000 且输入在[0,1000]，按比例映射，否则夹取 */
static inline int map_coord_input_to_device_local(int v, int minv, int maxv) {
    if (maxv > 1000 && v >= 0 && v <= 1000) {
        int span = maxv - minv;
        int scaled = minv + (v * span) / 1000;
        return clampi(scaled, minv, maxv);
    }
    return clampi(v, minv, maxv);
}

/* 判定是否为触摸相关事件（用于过滤真实硬件事件） */
static inline bool is_touch_event(unsigned int type, unsigned int code) {
    if (type == EV_ABS) {
        return code == ABS_MT_SLOT ||
               code == ABS_MT_TRACKING_ID ||
               code == ABS_MT_POSITION_X ||
               code == ABS_MT_POSITION_Y ||
               code == ABS_X ||
               code == ABS_Y;
    }
    if (type == EV_KEY) {
        return code == BTN_TOUCH || code == BTN_TOOL_FINGER;
    }
    return false;
}

/* input_event 替换：在启用且目标设备时，丢弃真实触摸事件（非触摸或非目标设备透传） */
static void input_event_replace(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
    if (atomic_read(&g_inject_enabled) == 0 || dev != g_target_dev) {
        /* 未启用或非目标设备：透传 */
        orig_input_event(dev, type, code, value);
        return;
    }

    /* 我们的注入路径正在进行：透传（避免被自己钩住） */
    if (atomic_read(&g_inject_in_progress) > 0) {
        orig_input_event(dev, type, code, value);
        return;
    }

    /* 目标设备的真实触摸事件：直接丢弃；非触摸类（例如电源键）透传 */
    if (is_touch_event(type, code)) {
        /* 严格独占：丢弃真实触摸事件 */
        return;
    } else {
        orig_input_event(dev, type, code, value);
    }
}

/* 注入一个 MT-B 帧（DOWN/MOVE/UP），mirror ABS_X/ABS_Y（若存在） */
static void injector_emit_point(struct input_dev *dev, const TOUCH_POINT *pt)
{
    int xmin, xmax, ymin, ymax;
    int mx, my;
    struct inj_slot_state *s;

    if (!dev || !pt) return;

    get_abs_bounds_local(dev, ABS_MT_POSITION_X, &xmin, &xmax);
    get_abs_bounds_local(dev, ABS_MT_POSITION_Y, &ymin, &ymax);

    if (pt->slot >= INJ_MAX_SLOTS) return;
    s = &g_inj_slots[pt->slot];

    switch (pt->action) {
        case TOUCH_ACTION_DOWN: {
            bool need_keys_down = (g_inj_active_touches == 0);

            if (!s->active) {
                s->active = true;
                if (g_inj_next_tracking_id == -1) g_inj_next_tracking_id = 1;
                s->tracking_id = g_inj_next_tracking_id++;
                if (g_inj_next_tracking_id <= 0) g_inj_next_tracking_id = 1;
                g_inj_active_touches++;
            }
            mx = map_coord_input_to_device_local(pt->x, xmin, xmax);
            my = map_coord_input_to_device_local(pt->y, ymin, ymax);
            s->x = mx; s->y = my;

            /* 递归保护开启：我们的注入必须透传到 orig_input_event */
            atomic_inc(&g_inject_in_progress);

            input_mt_slot(dev, pt->slot);
            input_report_abs(dev, ABS_MT_TRACKING_ID, s->tracking_id);
            input_report_abs(dev, ABS_MT_POSITION_X, s->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, s->y);
            if (has_abs_local(dev, ABS_X)) input_report_abs(dev, ABS_X, s->x);
            if (has_abs_local(dev, ABS_Y)) input_report_abs(dev, ABS_Y, s->y);
            /* BTN_* 下发仅在需要时由 cleanup 收尾统一处理，避免 UI 长按误判 */
            input_sync(dev);

            atomic_dec(&g_inject_in_progress);
            break;
        }
        case TOUCH_ACTION_MOVE: {
            if (s->active) {
                int nx = map_coord_input_to_device_local(pt->x, xmin, xmax);
                int ny = map_coord_input_to_device_local(pt->y, ymin, ymax);
                s->x = nx; s->y = ny;

                atomic_inc(&g_inject_in_progress);

                input_mt_slot(dev, pt->slot);
                input_report_abs(dev, ABS_MT_POSITION_X, s->x);
                input_report_abs(dev, ABS_MT_POSITION_Y, s->y);
                if (has_abs_local(dev, ABS_X)) input_report_abs(dev, ABS_X, s->x);
                if (has_abs_local(dev, ABS_Y)) input_report_abs(dev, ABS_Y, s->y);
                input_sync(dev);

                atomic_dec(&g_inject_in_progress);
            }
            break;
        }
        case TOUCH_ACTION_UP: {
            if (s->active) {
                atomic_inc(&g_inject_in_progress);

                input_mt_slot(dev, pt->slot);
                input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
                s->active = false;
                s->tracking_id = -1;
                if (g_inj_active_touches > 0) g_inj_active_touches--;
                /* 不立即下发 BTN_*，由统一收尾决定 */
                input_sync(dev);

                atomic_dec(&g_inject_in_progress);
            }
            break;
        }
        default:
            break;
    }
}

/* 统一收尾：释放所有活跃 slot，并条件性补发 BTN_TOUCH/BTN_TOOL_FINGER 0 */
static void injector_emit_cleanup(struct input_dev *dev)
{
    int i;
    bool any_release = false;

    if (!dev) return;

    atomic_inc(&g_inject_in_progress);

    for (i = 0; i < INJ_MAX_SLOTS; ++i) {
        struct inj_slot_state *st = &g_inj_slots[i];
        if (st->active) {
            input_mt_slot(dev, i);
            input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
            st->active = false;
            st->tracking_id = -1;
            any_release = true;
        }
    }
    if (any_release) {
        g_inj_active_touches = 0;
        /* 条件性补发 BTN_* 收尾（若设备有这些键位） */
        if (has_key_local(dev, BTN_TOOL_FINGER)) input_report_key(dev, BTN_TOOL_FINGER, 0);
        if (has_key_local(dev, BTN_TOUCH)) input_report_key(dev, BTN_TOUCH, 0);
        input_sync(dev);
    }

    atomic_dec(&g_inject_in_progress);
}

/* 注入线程：等待通知，消费共享缓冲区生成 MT-B 帧 */
static int injector_thread_fn(void *data)
{
    TOUCH_SHARED_BUFFER *buf;
    struct input_dev *dev;
    TOUCH_POINT pt;

    /* 初始化本地状态 */
    int i;
    for (i = 0; i < INJ_MAX_SLOTS; ++i) {
        g_inj_slots[i].tracking_id = -1;
        g_inj_slots[i].x = 0;
        g_inj_slots[i].y = 0;
        g_inj_slots[i].active = false;
    }
    g_inj_active_touches = 0;
    g_inj_next_tracking_id = 1;

    buf = touch_get_shared_buffer();

    while (!kthread_should_stop()) {
        /* 等待：有数据或启用但需要清理 */
        wait_event_interruptible(g_inject_wait,
            kthread_should_stop() ||
            (atomic_read(&g_inject_enabled) && buf && (buf->head != buf->tail))
        );

        if (kthread_should_stop())
            break;

        /* 快照设备指针以避免竞态 */
        mutex_lock(&g_inject_lock);
        dev = g_target_dev;
        mutex_unlock(&g_inject_lock);

        if (!dev || !atomic_read(&g_inject_enabled) || !buf) {
            /* 未启用或无设备或无缓冲，继续等待 */
            schedule_timeout_interruptible(msecs_to_jiffies(10));
            continue;
        }

        /* 消费一个点（与原 hook_read 节奏一致） */
        if (buf->head != buf->tail) {
            pt = buf->points[buf->tail];
            buf->tail = (buf->tail + 1) % TOUCH_BUFFER_POINTS;

            injector_emit_point(dev, &pt);
        }
    }

    return 0;
}

/* API 实现 */

int injector_init(void)
{
    init_waitqueue_head(&g_inject_wait);
    atomic_set(&g_inject_enabled, 0);
    atomic_set(&g_inject_in_progress, 0);
    g_target_dev = NULL;
    g_inject_thread = NULL;

    /* 解析 input_event 符号 */
    k_input_event = (void *)kallsyms_lookup_name("input_event");
    if (!k_input_event) {
        PRINT_DEBUG("[-] injector: failed to resolve input_event symbol\n");
        return -ENOENT;
    }

    /* 未安装钩子，等待 enable 时安装 */
    return 0;
}

void injector_exit(void)
{
    /* 停止线程 */
    if (g_inject_thread) {
        kthread_stop(g_inject_thread);
        g_inject_thread = NULL;
    }
    /* 卸载钩子 */
    if (k_input_event && orig_input_event) {
        unhook((void *)k_input_event);
        orig_input_event = NULL;
    }
    g_target_dev = NULL;
    atomic_set(&g_inject_enabled, 0);
}

/* 开启：绑定设备、安装钩子，启动注入线程 */
int injector_enable(struct input_dev *dev)
{
    int i;

    if (!dev) return -EINVAL;

    mutex_lock(&g_inject_lock);

    g_target_dev = dev;

    /* 安装 input_event 钩子（仅一次） */
    if (k_input_event && !orig_input_event) {
        hook_err_t rc = hook((void *)k_input_event, (void *)input_event_replace, (void **)&orig_input_event);
        if (rc != HOOK_NO_ERR || !orig_input_event) {
            PRINT_DEBUG("[-] injector: hook input_event failed rc=%d\n", rc);
            mutex_unlock(&g_inject_lock);
            return -EFAULT;
        }
        PRINT_DEBUG("[+] injector: input_event hooked\n");
    }

    /* 重置本地状态 */
    for (i = 0; i < INJ_MAX_SLOTS; ++i) {
        g_inj_slots[i].tracking_id = -1;
        g_inj_slots[i].x = 0;
        g_inj_slots[i].y = 0;
        g_inj_slots[i].active = false;
    }
    g_inj_active_touches = 0;
    g_inj_next_tracking_id = 1;

    /* 启动线程（若尚未启动） */
    if (!g_inject_thread) {
        g_inject_thread = kthread_run(injector_thread_fn, NULL, "khack_inject");
        if (IS_ERR(g_inject_thread)) {
            PRINT_DEBUG("[-] injector: kthread_run failed\n");
            g_inject_thread = NULL;
            mutex_unlock(&g_inject_lock);
            return -EFAULT;
        }
    }

    atomic_set(&g_inject_enabled, 1);

    /* 轻唤醒一次，便于立即消费缓冲 */
    wake_up_interruptible(&g_inject_wait);

    mutex_unlock(&g_inject_lock);
    PRINT_DEBUG("[+] injector: enabled on dev=%s\n", dev->name);
    return 0;
}

/* 禁用：强制清理 + 卸载钩子 + 停止线程 */
void injector_disable(void)
{
    struct input_dev *dev;

    mutex_lock(&g_inject_lock);
    dev = g_target_dev;
    /* 标记禁用，避免后续过滤 */
    atomic_set(&g_inject_enabled, 0);
    mutex_unlock(&g_inject_lock);

    if (dev) {
        injector_force_cleanup();
    }

    /* 停止线程 */
    if (g_inject_thread) {
        kthread_stop(g_inject_thread);
        g_inject_thread = NULL;
    }

    /* 卸载钩子 */
    if (k_input_event && orig_input_event) {
        unhook((void *)k_input_event);
        orig_input_event = NULL;
        PRINT_DEBUG("[+] injector: input_event unhooked\n");
    }

    mutex_lock(&g_inject_lock);
    g_target_dev = NULL;
    mutex_unlock(&g_inject_lock);
}

/* 唤醒注入线程 */
void injector_notify(void)
{
    wake_up_interruptible(&g_inject_wait);
}

/* 强制清理所有活跃触点，条件性补发 BTN_*，并 input_sync */
void injector_force_cleanup(void)
{
    struct input_dev *dev;

    mutex_lock(&g_inject_lock);
    dev = g_target_dev;
    mutex_unlock(&g_inject_lock);

    if (!dev) return;

    injector_emit_cleanup(dev);
}

/* 导出符号（可选） */
EXPORT_SYMBOL(injector_init);
EXPORT_SYMBOL(injector_exit);
EXPORT_SYMBOL(injector_enable);
EXPORT_SYMBOL(injector_disable);
EXPORT_SYMBOL(injector_notify);
EXPORT_SYMBOL(injector_force_cleanup);