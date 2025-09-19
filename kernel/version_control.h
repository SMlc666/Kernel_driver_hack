#ifndef VERSION_CONTROL_H
#define VERSION_CONTROL_H

#include <linux/printk.h>

// Set to 1 to enable debug prints, 0 to disable them.
#define DEBUG_PRINT 1

#if DEBUG_PRINT
    #define PRINT_DEBUG(fmt, ...) printk(KERN_INFO "[KHACK_DEBUG] " fmt, ##__VA_ARGS__)
#else
    #define PRINT_DEBUG(fmt, ...) do {} while(0)
#endif

#endif // VERSION_CONTROL_H
