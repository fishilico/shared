/**
 * Test the ARM64 implementation
 */
#include "arch_arm64.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    asm_instr_context ctx;
    const uintptr_t data_addr = 0xda7a0000;
    uint8_t data[] = "\x17\x15\x7e\x57\xda\x7a\xb1\x0b It is test data blob";
    int retval = 0;
    asm_instr_reg data64h;
    const asm_instr_reg data64 = 0x0bb17ada577e1517UL;
    const asm_instr_reg data8 = data64 & 0xff;

    memcpy(&data64h, &data[8], sizeof(asm_instr_reg));
    memset(&ctx, 0, sizeof(ctx));

#define test(opcode, instrstr, reg, val) \
    do { \
        char asm_instr[ASM_INSTR_BUFSIZE] = ""; \
        const uint8_t instructions[] = opcode; \
        asm_instr_reg final_pc = (asm_instr_reg)&(instructions[sizeof(instructions) - 1]); \
        R_PC(&ctx) = (asm_instr_reg)&instructions; \
        if (!run_mov_asm_instruction_p(&ctx, data_addr, data, sizeof(data), asm_instr)) { \
            printf("[FAIL] %-24s %s\n", #opcode, instrstr); \
            retval = 1; \
        } else if (strcmp(asm_instr, instrstr)) { \
            printf("[FAIL] %-24s\n...  decoded '%s'\n... expected '%s'\n", \
                   #opcode, asm_instr, instrstr); \
            retval = 1; \
        } else if (R_##reg(&ctx) != (val)) { \
            printf("[FAIL] %-24s %s: %s = 0x%" PRIxREG ", expected 0x%" PRIxREG "\n", \
                   #opcode, instrstr, #reg, (uint64_t)R_##reg(&ctx), (uint64_t)(val)); \
            retval = 1; \
        } else if (R_PC(&ctx) != final_pc) { \
            printf("[FAIL] %-24s %s: PC is 0x%" PRIxREG " instead of 0x%" PRIxREG "\n", \
                   #opcode, instrstr, R_PC_U(&ctx), (uint64_t)final_pc); \
            retval = 1; \
        } else { \
            printf("[ OK ] %-24s %-36s ; %-3s = 0x%" PRIxREG "\n", \
                   #opcode, instrstr, #reg, (uint64_t)R_##reg(&ctx)); \
        } \
        memset(&ctx, 0xff, sizeof(ctx)); \
    } while (0)

    /* Load byte (ldrb). It zero-extends in the 64-bit register */
    R_X0(&ctx) = data_addr - 0x2a;
    R_X2(&ctx) = 0x100000000;
    test("\x02\xa8\x40\x39", "ldrb w2, [x0=0xda79ffd6, #0x2a]", X0, 0xda79ffd6);
    R_X0(&ctx) = data_addr - 0x2a;
    R_X2(&ctx) = 0x100000000;
    test("\x02\xa8\x40\x39", "ldrb w2, [x0=0xda79ffd6, #0x2a]", X2, data8);

    R_X1(&ctx) = data_addr;
    test("\x20\x14\x40\x38", "ldrb w0, [x1=0xda7a0000], #0x1", X0, data8);
    R_X1(&ctx) = data_addr;
    test("\x20\x14\x40\x38", "ldrb w0, [x1=0xda7a0000], #0x1", X1, 0xda7a0001);

    R_X1(&ctx) = data_addr - 1;
    test("\x20\x1c\x40\x38", "ldrb w0, [x1=0xda79ffff, #0x1]!", X0, data8);
    R_X1(&ctx) = data_addr - 1;
    test("\x20\x1c\x40\x38", "ldrb w0, [x1=0xda79ffff, #0x1]!", X1, 0xda7a0000);

    R_X1(&ctx) = data_addr + 1;
    test("\x20\xfc\x5f\x38", "ldrb w0, [x1=0xda7a0001, #-0x1]!", X0, data8);
    R_X1(&ctx) = data_addr + 1;
    test("\x20\xfc\x5f\x38", "ldrb w0, [x1=0xda7a0001, #-0x1]!", X1, 0xda7a0000);

    /* Load pair (ldp) */
    R_X0(&ctx) = data_addr;
    test("\x02\x0c\x40\xa9", "ldp x2, x3, [x0=0xda7a0000]", X0, 0xda7a0000);
    R_X0(&ctx) = data_addr;
    test("\x02\x0c\x40\xa9", "ldp x2, x3, [x0=0xda7a0000]", X2, data64);
    R_X0(&ctx) = data_addr;
    test("\x02\x0c\x40\xa9", "ldp x2, x3, [x0=0xda7a0000]", X3, data64h);

    R_X1(&ctx) = data_addr - 0x20;
    test("\x22\x0c\xc2\xa9", "ldp x2, x3, [x1=0xda79ffe0, #0x20]!", X1, 0xda7a0000);
    R_X1(&ctx) = data_addr - 0x20;
    test("\x22\x0c\xc2\xa9", "ldp x2, x3, [x1=0xda79ffe0, #0x20]!", X2, data64);
    R_X1(&ctx) = data_addr - 0x20;
    test("\x22\x0c\xc2\xa9", "ldp x2, x3, [x1=0xda79ffe0, #0x20]!", X3, data64h);

    /* Load a register byte (unscaled) */
    R_X3(&ctx) = data_addr + 1;
    test("\x64\xf0\x5f\x38", "ldurb w4, [x3=0xda7a0001, #-0x1]", X3, 0xda7a0001);
    R_X3(&ctx) = data_addr + 1;
    test("\x64\xf0\x5f\x38", "ldurb w4, [x3=0xda7a0001, #-0x1]", X4, data8);

    return retval;
}
