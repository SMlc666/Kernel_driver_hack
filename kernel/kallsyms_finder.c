#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/init_task.h> // For init_task
#include <asm/byteorder.h>

#include "kallsyms_finder.h"
#include "version_control.h"

// Use kernel's standard symbols for text section
extern char _stext[], _etext[];

// Data structures to hold the found offsets and info
struct kallsyms_info {
    unsigned long addresses_off;
    unsigned long num_syms_off;
    unsigned long names_off;
    unsigned long markers_off;
    unsigned long token_table_off;
    unsigned long token_index_off;

    unsigned long relative_base;
    bool has_base_relative;

    unsigned long num_syms;
    int ptr_size;
    bool is_big_endian;
};

static void *memsearch(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    const char *p;
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;

    for (p = (const char *)haystack; p <= (const char *)haystack + haystacklen - needlelen; p++) {
        if (memcmp(p, needle, needlelen) == 0)
            return (void *)p;
    }
    return NULL;
}

static unsigned long find_kallsyms_token_table(unsigned long start, unsigned long end) {
    const char pattern[] = { '0', 0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0, '7', 0, '8', 0, '9', 0 };
    unsigned char *p;

    for (p = (unsigned char *)start; p < (unsigned char *)end - sizeof(pattern); p++) {
        if (memcmp(p, pattern, sizeof(pattern)) == 0) {
            unsigned char *candidate = p;
            int i, j;

            candidate--; // on '\0' before '0'
            for (i = 0; i < '0'; i++) {
                for (j = 0; j < 50; j++) {
                    if (candidate <= (unsigned char *)start) break;
                    candidate--;
                    if (*candidate == 0) break;
                }
                if (j == 50 || candidate <= (unsigned char *)start) {
                    candidate = NULL;
                    break;
                }
            }

            if (candidate) {
                unsigned long table_addr = (unsigned long)(candidate + 1);
                table_addr = (table_addr + 3) & ~3UL;
                PRINT_DEBUG("[kallsyms_finder] Found candidate for kallsyms_token_table at 0x%lx\n", table_addr);
                return table_addr;
            }
        }
    }
    return 0;
}

static int find_kallsyms_token_index(struct kallsyms_info *info) {
    u16 token_offsets[256];
    u16 be_token_offsets[256];
    unsigned char *p_token = (unsigned char *)info->token_table_off;
    unsigned char *search_start;
    int i;

    for (i = 0; i < 256; i++) {
        token_offsets[i] = p_token - (unsigned char *)info->token_table_off;
        while(*p_token++) {} // skip to next token
    }
    search_start = p_token;

    for (i = 0; i < 256; i++) {
        be_token_offsets[i] = cpu_to_be16(token_offsets[i]);
    }

    void *found_le = memsearch(search_start, 1024, token_offsets, sizeof(token_offsets));
    void *found_be = memsearch(search_start, 1024, be_token_offsets, sizeof(be_token_offsets));

    if (found_le) {
        info->is_big_endian = false;
        info->token_index_off = (unsigned long)found_le;
        PRINT_DEBUG("[kallsyms_finder] Found kallsyms_token_index (LE) at 0x%lx\n", info->token_index_off);
        return 0;
    } else if (found_be) {
        info->is_big_endian = true;
        info->token_index_off = (unsigned long)found_be;
        PRINT_DEBUG("[kallsyms_finder] Found kallsyms_token_index (BE) at 0x%lx\n", info->token_index_off);
        return 0;
    }

    PRINT_DEBUG("[kallsyms_finder] Failed to find kallsyms_token_index.\n");
    return -1;
}

static int find_kallsyms_markers(struct kallsyms_info *info) {
    unsigned long search_end = info->token_table_off;
    unsigned long candidate;

    info->ptr_size = sizeof(void*);

    for (candidate = (search_end - info->ptr_size) & ~(info->ptr_size - 1);
         candidate > search_end - 4096; 
         candidate -= info->ptr_size)
    {
        if (*(unsigned long*)candidate != 0) continue;

        unsigned long *markers = (unsigned long*)candidate;
        if (markers[1] > markers[0] && markers[2] > markers[1]) {
            info->markers_off = candidate;
            PRINT_DEBUG("[kallsyms_finder] Found kallsyms_markers at 0x%lx\n", info->markers_off);
            return 0;
        }
    }
    PRINT_DEBUG("[kallsyms_finder] Failed to find kallsyms_markers.\n");
    return -1;
}

static int find_kallsyms_names_and_num_syms(struct kallsyms_info *info) {
    unsigned long names_end = info->markers_off;
    unsigned long search_addr;

    for (search_addr = names_end - info->ptr_size; search_addr > names_end - 4096; search_addr -= info->ptr_size) {
        unsigned long num_syms_candidate = *(unsigned long*)search_addr;
        if (info->is_big_endian) num_syms_candidate = be64_to_cpu(num_syms_candidate);
        else num_syms_candidate = le64_to_cpu(num_syms_candidate);
        
        if (num_syms_candidate > 20000 && num_syms_candidate < 1000000) {
            unsigned long names_start_candidate = search_addr + info->ptr_size;
            unsigned char *p = (unsigned char *)names_start_candidate;
            unsigned long count = 0;
            while(count < num_syms_candidate && (unsigned long)p < names_end) {
                unsigned int len = *p++;
                if (len & 0x80) {
                    len = (len & 0x7f) | (*p++ << 7);
                }
                p += len;
                count++;
            }
            
            if (count == num_syms_candidate && (unsigned long)p <= names_end && (names_end - (unsigned long)p) < 4) {
                info->num_syms = num_syms_candidate;
                info->num_syms_off = search_addr;
                info->names_off = names_start_candidate;
                PRINT_DEBUG("[kallsyms_finder] Found kallsyms_num_syms at 0x%lx (count: %lu)\n", info->num_syms_off, info->num_syms);
                PRINT_DEBUG("[kallsyms_finder] Found kallsyms_names at 0x%lx\n", info->names_off);
                return 0;
            }
        }
    }
    PRINT_DEBUG("[kallsyms_finder] Failed to find kallsyms_num_syms and names.\n");
    return -1;
}

static int find_kallsyms_addresses(struct kallsyms_info *info) {
    // Simplified: assumes no relative base for now.
    info->has_base_relative = false;
    info->addresses_off = info->num_syms_off - (info->num_syms * info->ptr_size);
    info->addresses_off &= ~((unsigned long)info->ptr_size - 1);
    
    PRINT_DEBUG("[kallsyms_finder] Guessed kallsyms_addresses at 0x%lx\n", info->addresses_off);
    return 0;
}

static unsigned long get_symbol_address(struct kallsyms_info *info, unsigned long index) {
    unsigned long *p_addr = (unsigned long *)(info->addresses_off + index * info->ptr_size);
    unsigned long addr = *p_addr;
    if (info->is_big_endian) return be64_to_cpu(addr);
    return le64_to_cpu(addr);
}

static const char *get_symbol_name_and_type(struct kallsyms_info *info, unsigned long *p_name_offset, char *buffer, size_t buf_size) {
    unsigned char *p = (unsigned char *)(info->names_off + *p_name_offset);
    unsigned int len = *p++;
    if (len & 0x80) {
        len = (len & 0x7f) | (*p++ << 7);
    }
    
    unsigned int name_len = 0;
    buffer[0] = '\0';
    
    unsigned int i;
    for (i = 0; i < len; i++) {
        unsigned char token_index_val = *p++;
        u16 *p_token_index_table = (u16*)info->token_index_off;
        u16 token_offset;
        
        if (info->is_big_endian) token_offset = be16_to_cpu(p_token_index_table[token_index_val]);
        else token_offset = le16_to_cpu(p_token_index_table[token_index_val]);
        
        char *token = (char *)(info->token_table_off + token_offset);
        size_t token_len = strlen(token);
        
        if (name_len + token_len < buf_size) {
            strcat(buffer, token);
            name_len += token_len;
        }
    }
    
    *p_name_offset = (unsigned long)p - info->names_off;
    return buffer;
}

unsigned long kallsyms_lookup_name_by_scan(const char *name) {
    unsigned long start_addr, end_addr;
    struct kallsyms_info info;
    unsigned long i;
    unsigned long name_offset = 0;
    char name_buf[128]; // KSYM_NAME_LEN

    start_addr = (unsigned long)_stext;
    end_addr = (unsigned long)_etext;

    PRINT_DEBUG("[kallsyms_finder] Scanning kernel text from 0x%lx (_stext) to 0x%lx (_etext)\n", start_addr, end_addr);
    memset(&info, 0, sizeof(info));


    info.token_table_off = find_kallsyms_token_table(start_addr, end_addr);
    if (!info.token_table_off) return 0;

    if (find_kallsyms_token_index(&info) != 0) return 0;
    if (find_kallsyms_markers(&info) != 0) return 0;
    if (find_kallsyms_names_and_num_syms(&info) != 0) return 0;
    if (find_kallsyms_addresses(&info) != 0) return 0;

    PRINT_DEBUG("[kallsyms_finder] All tables located. Starting symbol search for '%s'...\n", name);

    for (i = 0; i < info.num_syms; i++) {
        const char *full_name = get_symbol_name_and_type(&info, &name_offset, name_buf, sizeof(name_buf));
        if (strcmp(full_name + 1, name) == 0) { // +1 to skip type character
            unsigned long addr = get_symbol_address(&info, i);
            PRINT_DEBUG("[kallsyms_finder] Found symbol '%s' at address 0x%lx\n", name, addr);
            return addr;
        }
    }

    PRINT_DEBUG("[kallsyms_finder] Symbol '%s' not found.\n", name);
    return 0;
}
