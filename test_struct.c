#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct _SINGLE_STEP_CTL
{
    pid_t tid;
    int action;
    uintptr_t regs_buffer;
} SINGLE_STEP_CTL, *PSINGLE_STEP_CTL;

int main() {
    SINGLE_STEP_CTL ctl = {10862, 5, 0x12345678};

    printf("sizeof(SINGLE_STEP_CTL) = %zu\n", sizeof(SINGLE_STEP_CTL));
    printf("sizeof(pid_t) = %zu\n", sizeof(pid_t));
    printf("sizeof(int) = %zu\n", sizeof(int));
    printf("sizeof(uintptr_t) = %zu\n", sizeof(uintptr_t));
    printf("\n");
    printf("ctl.tid = %d (offset 0)\n", ctl.tid);
    printf("ctl.action = %d (offset %zu)\n", ctl.action, offsetof(SINGLE_STEP_CTL, action));
    printf("ctl.regs_buffer = 0x%lx (offset %zu)\n", ctl.regs_buffer, offsetof(SINGLE_STEP_CTL, regs_buffer));
    printf("\n");

    // 打印原始字节
    unsigned char *bytes = (unsigned char *)&ctl;
    printf("Raw bytes: ");
    for (size_t i = 0; i < sizeof(ctl); i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");

    return 0;
}
