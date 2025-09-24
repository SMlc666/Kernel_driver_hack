#ifndef KALLSYMS_FINDER_H
#define KALLSYMS_FINDER_H

#include <linux/types.h>

unsigned long kallsyms_lookup_name_by_scan(const char *name);

#endif // KALLSYMS_FINDER_H
