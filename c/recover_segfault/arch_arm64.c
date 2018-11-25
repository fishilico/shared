/**
 * ARM64 instruction set decoder
 *
 * Documentation:
 * https://static.docs.arm.com/ddi0487/ca/DDI0487C_a_armv8_arm.pdf
 * https://static.docs.arm.com/100898/0100/the_a64_Instruction_set_100898_0100.pdf
 */
#include "arch_arm64.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Get a general-purpose register from its number.
 *
 * If regname is not null, write the register name to it.  Its size must be at least 4 bytes.
 */
static asm_instr_reg *get_gp_reg(
    asm_instr_context *ctx, unsigned int regnum, unsigned int bitsize, char *regname)
{
    static const char *const x_regs[32] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
    };
    static const char *const w_regs[32] = {
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp",
    };
    asm_instr_reg *preg;

    assert(regnum < 32);
    assert(bitsize == 32 || bitsize == 64);

    if (regnum == 31) {
        preg = (asm_instr_reg *)&R_SP(ctx);
    } else {
        preg = (asm_instr_reg *)&R_X(ctx, regnum);
    }

    if (regname) {
        if (bitsize == 32) {
            snprintf(regname, 4, "%s", w_regs[regnum]);
        } else if (bitsize == 64) {
            snprintf(regname, 4, "%s", x_regs[regnum]);
        } else {
            abort(); /* unreachable */
        }
    }
    return preg;
}

/**
 * Handle ldr-like instruction, with writeback and post-indexing
 */
static char *handle_ldr(
    asm_instr_context *ctx, unsigned int reg, int offset, uintptr_t data_addr,
    void *data, unsigned int size, bool writeback, bool postindex, void *pvalue)
{
    uintptr_t address;
    char sz_reg[4], *sz_operand;

    sz_operand = malloc(sizeof("[rXX=0x, 0x]!") + 16 + 16);
    assert(sz_operand);

    address = *get_gp_reg(ctx, reg, 64, sz_reg);
    if (postindex) {
        if (offset >= 0) {
            sprintf(sz_operand, "[%s=%#" PRIxPTR "], #%#x", sz_reg, address, offset);
        } else {
            sprintf(sz_operand, "[%s=%#" PRIxPTR "], #-%#x", sz_reg, address, -offset);
        }
    } else {
        if (writeback) {
            if (offset >= 0) {
                sprintf(sz_operand, "[%s=%#" PRIxPTR ", #%#x]!", sz_reg, address, offset);
            } else {
                sprintf(sz_operand, "[%s=%#" PRIxPTR ", #-%#x]!", sz_reg, address, -offset);
            }
        } else {
            if (offset == 0) {
                sprintf(sz_operand, "[%s=%#" PRIxPTR "]", sz_reg, address);
            } else if (offset > 0) {
                sprintf(sz_operand, "[%s=%#" PRIxPTR ", #%#x]", sz_reg, address, offset);
            } else {
                sprintf(sz_operand, "[%s=%#" PRIxPTR ", #-%#x]", sz_reg, address, -offset);
            }
        }
        address += offset;
    }

    /* Check the computed address */
    if (address != data_addr) {
        fprintf(stderr, "Error: mem parameter '%s' does not use address %" PRIxPTR "\n",
                sz_operand, data_addr);
        free(sz_operand);
        return NULL;
    }

    /* Copy the real data */
    memcpy(pvalue, data, size);

    if (postindex) {
        assert(writeback);
        address += offset;
    }
    if (writeback) {
        *get_gp_reg(ctx, reg, 64, NULL) = address;
    }
    return sz_operand;
}

/**
 * Emulate an ASM instruction in the given context, with data the pseudo content at data_addr
 */
bool run_mov_asm_instruction_p(
    asm_instr_context *ctx, uintptr_t data_addr, uint8_t *data, size_t datalen,
    char *asm_instr)
{
    const uint32_t instr = *(uint32_t *)(R_PC(ctx));
    unsigned int rn, rt, rt2;
    bool writeback, postindex;
    int imm7, imm9, uimm12;
    asm_instr_reg *p_target_reg;
    char sz_target_reg[4], sz_target_reg2[4], *sz_ldr_op = NULL;

    /* LDRB (Load byte, immediate offset) */
    if ((instr & 0xffc00000) == 0x39400000) {
        rt = instr & 0x1f;
        rn = (instr & 0x3e0) >> 5;
        uimm12 = (instr & 0x3ffc00) >> 10;
        p_target_reg = get_gp_reg(ctx, rt, 32, sz_target_reg);
        sz_ldr_op = handle_ldr(
            ctx, rn, uimm12, data_addr, data, 1, false, false, p_target_reg);
        if (!sz_ldr_op) {
            return false;
        }
        /* The value is zero-extended to the target register */
        memset(((uint8_t *)p_target_reg) + 1, 0, 7);
        asm_printf(asm_instr, "ldrb %s, %s", sz_target_reg, sz_ldr_op);
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }
    if ((instr & 0xffc00400) == 0x38400400) {
        rt = instr & 0x1f;
        rn = (instr & 0x3e0) >> 5;
        postindex = !(instr & 0x800);
        imm9 = (instr & 0x3ff000) >> 12;
        if (imm9 & 0x100) {
            /* Negative offset */
            imm9 -= 0x200;
        }
        p_target_reg = get_gp_reg(ctx, rt, 32, sz_target_reg);
        sz_ldr_op = handle_ldr(
            ctx, rn, imm9, data_addr, data, 1, true, postindex, p_target_reg);
        if (!sz_ldr_op) {
            return false;
        }
        /* The value is zero-extended to the target register */
        memset(((uint8_t *)p_target_reg) + 1, 0, 7);
        asm_printf(asm_instr, "ldrb %s, %s", sz_target_reg, sz_ldr_op);
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }

    /* LDP (Load pair) */
    if ((instr & 0xfe400000) == 0xa8400000) {
        assert(datalen >= 16);
        rt = instr & 0x1f;
        rn = (instr & 0x3e0) >> 5;
        rt2 = (instr & 0x7c00) >> 10;
        imm7 = (instr & 0x3f8000) >> 15;
        writeback = !!(instr & 0x800000);
        postindex = !(instr & 0x1000000);
        assert((instr & 0x1800000) != 0); /* No postindex without writeback */
        if (imm7 & 0x40) {
            imm7 -= 0x80;
        }
        imm7 *= 8;
        p_target_reg = get_gp_reg(ctx, rt, 64, sz_target_reg);
        sz_ldr_op = handle_ldr(
            ctx, rn, imm7, data_addr, data, 8, writeback, postindex, p_target_reg);
        if (!sz_ldr_op) {
            return false;
        }
        /* Copy the second register */
        memcpy(get_gp_reg(ctx, rt2, 64, sz_target_reg2), data + 8, 8);
        asm_printf(asm_instr, "ldp %s, %s, %s", sz_target_reg, sz_target_reg2, sz_ldr_op);
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }

    /* LDURB (Load an unscaled register byte) */
    if ((instr & 0xffe00c00) == 0x38400000) {
        rt = instr & 0x1f;
        rn = (instr & 0x3e0) >> 5;
        imm9 = (instr & 0x3ff000) >> 12;
        if (imm9 & 0x100) {
            imm9 -= 0x200;
        }
        p_target_reg = get_gp_reg(ctx, rt, 32, sz_target_reg);
        sz_ldr_op = handle_ldr(
            ctx, rn, imm9, data_addr, data, 1, false, false, p_target_reg);
        if (!sz_ldr_op) {
            return false;
        }
        /* The value is zero-extended to the target register */
        memset(((uint8_t *)p_target_reg) + 1, 0, 7);
        asm_printf(asm_instr, "ldurb %s, %s", sz_target_reg, sz_ldr_op);
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }

    fprintf(stderr, "Unknown ARM64 instruction @%p: 0x%08x\n",
            (const void *)R_PC(ctx), instr);
    return false;
}
