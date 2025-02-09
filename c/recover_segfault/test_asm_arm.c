/**
 * Test the ARM implementation
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "arch_arm.h"

int main(void)
{
    asm_instr_context ctx;
    const uintptr_t data_addr = 0xda7a0000;
    uint8_t data[] = "\x17\x15\xda\x7a It is data";
    int retval = 0;
    const asm_instr_reg data32 = 0x7ada1517UL;
    const asm_instr_reg data16 = data32 & 0xffff;
    const asm_instr_reg data8 = data32 & 0xff;
    asm_instr_reg data32h;

    memcpy(&data32h, &data[4], sizeof(asm_instr_reg));
    memset(&ctx, 0, sizeof(ctx));

    /* Check that asm_instr_ctx_reg_bynum gives same result as R_* macros,
     * which internally uses asm_instr_ctx_reg
     */
    #define _check_asm_instr_ctx_reg(ctx, num, name) \
        assert(&asm_instr_ctx_reg_bynum(ctx, num) == &R_##name(ctx))
    #define check_asm_instr_ctx_reg(num, name) \
        _check_asm_instr_ctx_reg((asm_instr_context *)NULL, num, name)
    check_asm_instr_ctx_reg(0, R0);
    check_asm_instr_ctx_reg(1, R1);
    check_asm_instr_ctx_reg(2, R2);
    check_asm_instr_ctx_reg(3, R3);
    check_asm_instr_ctx_reg(4, R4);
    check_asm_instr_ctx_reg(5, R5);
    check_asm_instr_ctx_reg(6, R6);
    check_asm_instr_ctx_reg(7, R7);
    check_asm_instr_ctx_reg(8, R8);
    check_asm_instr_ctx_reg(9, R9);
    check_asm_instr_ctx_reg(10, R10);
    check_asm_instr_ctx_reg(11, FP);
    check_asm_instr_ctx_reg(12, IP);
    check_asm_instr_ctx_reg(13, SP);
    check_asm_instr_ctx_reg(14, LR);
    check_asm_instr_ctx_reg(15, PC);

#define test(_opcode, instrstr, reg, val) \
    do { \
        char asm_instr[ASM_INSTR_BUFSIZE] = ""; \
        uint32_t opcode = (_opcode); \
        uint8_t instructions[sizeof(opcode)]; \
        asm_instr_reg final_pc = (asm_instr_reg)&(instructions[sizeof(opcode)]); \
        memcpy(instructions, &opcode, sizeof(opcode)); \
        R_PC(&ctx) = (asm_instr_reg)&instructions; \
        if (!run_mov_asm_instruction_p(&ctx, data_addr, data, sizeof(data), asm_instr)) { \
            printf("[FAIL] 0x%08x %s\n", opcode, instrstr); \
            retval = 1; \
        } else if (strcmp(asm_instr, instrstr)) { \
            printf("[FAIL] 0x%08x\n...  decoded '%s'\n... expected '%s'\n", \
                   opcode, asm_instr, instrstr); \
            retval = 1; \
        } else if (R_##reg(&ctx) != (val)) { \
            printf("[FAIL] 0x%08x %s: %s = 0x%" PRIxREG ", expected 0x%" PRIxREG "\n", \
                   opcode, instrstr, #reg, (uint32_t)R_##reg(&ctx), (uint32_t)(val)); \
            retval = 1; \
        } else if (R_PC(&ctx) != final_pc) { \
            printf("[FAIL] 0x%08x %s: PC is 0x%" PRIxREG " instead of 0x%" PRIxREG "\n", \
                   opcode, instrstr, R_PC_U(&ctx), (uint32_t)final_pc); \
            retval = 1; \
        } else { \
            printf("[ OK ] 0x%08x %-36s ; %-3s = 0x%" PRIxREG "\n", \
                   opcode, instrstr, #reg, (uint32_t)R_##reg(&ctx)); \
        } \
        memset(&ctx, 0, sizeof(ctx)); \
    } while (0)

    /* Load byte from indirect register */
    R_R0(&ctx) = data_addr;
    test(0xe5902000, "ldr r2, [r0=0xda7a0000]", R2, data32);
    R_R0(&ctx) = data_addr - 42;
    test(0xe5d0402a, "ldrb r4, [r0=0xda79ffd6, #0x2a]", R4, data8);
    R_R0(&ctx) = data_addr + 42;
    test(0xe550402a, "ldrb r4, [r0=0xda7a002a, #-0x2a]", R4, data8);

    /* "pop {r4}" can be encoded "ldr r4, [sp], #4" */
    R_SP(&ctx) = data_addr;
    test(0xe49d4004, "ldr r4, [sp=0xda7a0000], #0x4", R4, data32);
    R_SP(&ctx) = data_addr;
    test(0xe49d4004, "ldr r4, [sp=0xda7a0000], #0x4", SP, 0xda7a0004);

    /* Load with write-back */
    R_R0(&ctx) = data_addr - 1;
    test(0xe5f02001, "ldrb r2, [r0=0xda79ffff, #0x1]!", R2, data8);
    R_R0(&ctx) = data_addr - 1;
    test(0xe5f02001, "ldrb r2, [r0=0xda79ffff, #0x1]!", R0, data_addr);

    /* Load half-word and signed byte and half-word */
    R_R0(&ctx) = data_addr - 3;
    test(0xe1d010b3, "ldrh r1, [r0=0xda79fffd, #0x3]", R1, data16);
    R_R0(&ctx) = data_addr - 3;
    test(0xe1d010d3, "ldrsb r1, [r0=0xda79fffd, #0x3]", R1, data8);
    R_R0(&ctx) = data_addr - 3;
    test(0xe1d010f3, "ldrsh r1, [r0=0xda79fffd, #0x3]", R1, data16);

    /* Load register dual with post-increment */
    R_R0(&ctx) = data_addr;
    test(0xe0c020d8, "ldrd r2, r3, [r0=0xda7a0000], #0x8", R2, data32);
    R_R0(&ctx) = data_addr;
    test(0xe0c020d8, "ldrd r2, r3, [r0=0xda7a0000], #0x8", R3, data32h);
    R_R0(&ctx) = data_addr;
    test(0xe0c020d8, "ldrd r2, r3, [r0=0xda7a0000], #0x8", R0, data_addr + 8);

    /* Load multiple */
    R_R1(&ctx) = data_addr;
    test(0xe8b100f0, "ldm r1=0xda7a0000!, {r4, r5, r6, r7}", R4, data32);
    R_R1(&ctx) = data_addr;
    test(0xe8b100f0, "ldm r1=0xda7a0000!, {r4, r5, r6, r7}", R5, data32h);
    R_R1(&ctx) = data_addr;
    test(0xe8b100f0, "ldm r1=0xda7a0000!, {r4, r5, r6, r7}", R1, data_addr + 16);
    return retval;
}
