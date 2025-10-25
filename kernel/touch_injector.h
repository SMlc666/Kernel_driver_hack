/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * touch_injector.h
 * 核心层最小注入/钩子接口：真实设备注入、严格独占、不新增设备、不动 read/poll
 */

#ifndef KHACK_TOUCH_INJECTOR_H
#define KHACK_TOUCH_INJECTOR_H

#include <linux/types.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/mutex.h>
#include <linux/wait.h>

/*
 * 初始化/反初始化注入子系统
 * 在 [touch_input_init()](kernel/touch_input.c:151) / [touch_input_exit()](kernel/touch_input.c:197) 中调用
 */
int injector_init(void);
void injector_exit(void);

/*
 * 启用/禁用注入：
 * - enable: 绑定目标真实触摸设备、安装 input_event 钩子、启动注入 worker
 * - disable: 强制清理（UP+SYN 等），卸载钩子，停止 worker
 */
int injector_enable(struct input_dev *dev);
void injector_disable(void);

/*
 * 唤醒注入 worker：当用户态发 [OP_TOUCH_NOTIFY](kernel/touch_input.c:299) 或 [OP_TOUCH_CLEAN_STATE](kernel/touch_input.c:313) 时调用
 */
void injector_notify(void);

/*
 * 强制清理所有活跃 slot：
 * - 对每个 slot 发送 TRACKING_ID -1
 * - 条件性补发 BTN_TOUCH 0 / BTN_TOOL_FINGER 0（按能力位判断）
 * - 最终 input_sync
 * 在卸载 [OP_TOUCH_HOOK_UNINSTALL](kernel/touch_input.c:218) 或禁用模式时调用，确保不出现“长按卡住”
 */
void injector_force_cleanup(void);

#endif /* KHACK_TOUCH_INJECTOR_H */