# Kernel Driver Hack

一个功能强大的 Android/Linux 内核驱动，本项目 fork 自 [Jiang-Night/Kernel_driver_hack](https://github.com/Jiang-Night/Kernel_driver_hack)，并在其基础上进行了大量功能扩展和 Bug 修复。它旨在通过非常规方式提供对系统底层功能的访问，主要用于安全研究和学习目的。

> [!WARNING]
> 本项目仅供学习交流，严禁用于任何商业或非法用途。任何滥用本项目源码造成的后果由使用者自行承担。

## ✨ 核心功能

本驱动提供了一套通过 `ioctl` 控制的强大功能集，主要包括：

-   **内核级内存读写**:
    -   读取或写入任意进程的虚拟内存。
    -   支持跨页读写和安全读写模式 (`read_safe`)。
    -   获取进程中指定模块（如 `.so` 文件）的基地址。

-   **进程隐藏**:
    -   通过挂钩 VFS (Virtual File System) 层函数，从 `/proc` 目录和系统调用中隐藏指定 PID。
    -   通过挂钩 `sys_kill` 系统调用，防止被隐藏的进程被信号杀死。

-   **输入事件劫持与模拟**:
    -   **事件拦截**: 可通过设备名挂钩 (Hook) 指定的输入设备（如触摸屏）。
    -   **两种模式**:
        1.  **拦截模式 (`MODE_INTERCEPT`)**: 完全接管输入事件，事件不会传递给系统。
        2.  **透传模式 (`MODE_PASS_THROUGH`)**: 监视输入事件，但不影响其正常传递。
    -   **事件读取**: 在用户空间实时读取被劫持的原始输入事件。
    -   **事件注入**: 在用户空间构造并注入任意输入事件，实现高精度的模拟操作。
    -   **看门狗机制**: 客户端与驱动之间有心跳机制，若客户端超时未响应，驱动将自动解除挂钩，防止系统死锁。

-   **驱动隐蔽性**:
    -   模块加载后会从 `lsmod` 列表和 sysfs 文件系统中脱钩，实现基本的隐藏。

## 🛠️ 工作原理

为了避免创建显眼的设备文件 (`/dev/xxx`)，本驱动巧妙地劫持了 `/proc/version` 文件的 `unlocked_ioctl` 文件操作。

当用户层程序打开 `/proc/version` 并发送特定的 `ioctl` 命令时，驱动会拦截该请求并进入相应的处理流程。这种方式为用户层和内核层之间建立了一个隐蔽的通信渠道。

## 🚀 快速开始

### 编译

#### 1. 编译内核模块

-   **环境**: 你需要一个完整的内核源码树，并配置好交叉编译工具链。
-   **步骤**:
    1.  将 `kernel` 目录下的所有文件复制到内核源码的 `drivers/khack` (自定义) 目录下。
    2.  在上一级的 `drivers/Makefile` 和 `drivers/Kconfig` 中添加对 `khack` 目录的引用。
    3.  使用内核的构建系统进行编译，最终会生成 `my_driver.ko` 文件。

    ```makefile
    # drivers/Makefile
    obj-$(CONFIG_KERNEL_HACK) += khack/

    # drivers/Kconfig
    source "drivers/khack/Kconfig"
    ```

#### 2. 编译用户层程序

-   **环境**: aarch64 C++ 交叉编译工具链。
-   **步骤**:
    1.  进入 `user` 目录。
    2.  根据你的工具链路径修改 `Makefile` 中的 `CC` 变量。
    3.  执行 `make` 命令。

    ```bash
    cd user/
    make
    ```

### 使用

1.  **加载驱动**:
    ```shell
    insmod my_driver.ko
    ```

2.  **运行客户端**:
    -   将编译好的用户层程序（如 `hide_test`, `touch_comprehensive_test`）推送到设备上。
    -   给予执行权限并运行。
    ```shell
    adb push hide_test /data/local/tmp/
    adb shell
    cd /data/local/tmp/
    chmod +x hide_test
    ./hide_test
    ```

3.  **查看日志**:
    ```shell
    dmesg | grep "KHACK_DEBUG"
    ```

4.  **卸载驱动**:
    ```shell
    rmmod my_driver
    ```

## 📚 API 概览 (ioctl 命令)

所有操作都需要先执行 `OP_AUTHENTICATE` 进行认证。

| 命令                             | 十六进制值 | 功能描述                                                     |
| -------------------------------- | ---------- | ------------------------------------------------------------ |
| `OP_AUTHENTICATE`                | `0x7FF`    | 认证客户端进程，后续操作只接受该进程的请求。                 |
| `OP_READ_MEM` / `OP_READ_MEM_SAFE` | `0x801` / `0x809` | 读取目标进程内存。`_SAFE` 版本使用 `ioremap_nocache`。       |
| `OP_WRITE_MEM`                   | `0x802`    | 写入目标进程内存。                                           |
| `OP_MODULE_BASE`                 | `0x803`    | 获取目标进程中某个模块的基地址。                             |
| `OP_GET_PID`                     | `0x808`    | 根据进程名获取 PID。                                         |
| `OP_HIDE_PROC`                   | `0x804`    | 隐藏/取消隐藏/清空被隐藏的进程。                             |
| `OP_HOOK_INPUT_DEVICE`           | `0x810`    | **[推荐]** 按名称挂钩输入设备，启动事件劫持。                |
| `OP_UNHOOK_INPUT_DEVICE`         | `0x811`    | 解除输入设备挂钩。                                           |
| `OP_READ_INPUT_EVENTS`           | `0x812`    | 从内核缓冲区读取被劫持的输入事件包。                         |
| `OP_INJECT_INPUT_EVENT`          | `0x813`    | 注入单个输入事件。                                           |
| `OP_INJECT_INPUT_PACKAGE`        | `0x815`    | 注入一个事件包（多个事件）。                                 |
| `OP_SET_TOUCH_MODE`              | `0x816`    | 设置劫持模式（`MODE_PASS_THROUGH` 或 `MODE_INTERCEPT`）。      |
| `OP_HEARTBEAT`                   | `0x814`    | 客户端发送心跳以维持连接，防止被看门狗清理。                 |

## ❤️ 致谢

-   **当前开发者**: `SMlc666` (本项目的扩展和维护者)

本项目基于以下优秀项目和开发者的工作：

-   **原始项目**: 本项目 fork 自 [Jiang-Night/Kernel_driver_hack](https://github.com/Jiang-Night/Kernel_driver_hack)，感谢原作者 `JiagNight` 以及共创者 [Rogo](https://github.com/rogxo/kernel_hack)、[LuMing](https://github.com/smm800) 和 [小黑](https://github.com/GameCheatExpert) 的初始工作。

-   **设计参考**:
    -   `inline hook` 和 `get_sys_call_table` 的实现方式参考了 [bmax121/kernelpatch](https://github.com/bmax121/kernelpatch) 和 [stdhu/kernel-inline-hook](https://github.com/stdhu/kernel-inline-hook) 的设计。

感谢所有为本项目及相关技术做出贡献的开发者。

## 📜 许可证

本项目采用 [GNU General Public License v3.0](LICENSE) 许可证。
