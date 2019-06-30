/**
 * ARM instruction set decoder
 *
 * Documentation:
 * * http://infocenter.arm.com/help/topic/com.arm.doc.qrc0001m/QRC0001_UAL.pdf
 *   ARM and Thumb-2 Instruction Set - Quick Reference Card
 * * http://re-eject.gbadev.org/files/armref.pdf
 *   ARM opcodes reference - rE-Ejected
 * * http://simplemachines.it/doc/arm_inst.pdf
 *   The ARM Instruction Set - ARM University Program - V1.0
 * * https://www.opensource.apple.com/source/lldb/lldb-69/llvm/lib/Target/ARM/Disassembler/ARMDisassembler.cpp
 *   The LLVM Compiler Infrastructure - part of the ARM Disassembler
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* for snprintf */
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch_arm.h"

static const char *const reg_names[16] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc",
};

/**
 * Get a general-purpose register from its number.
 *
 * If regname is not null, write the register name to it.  Its size must be at least 4 bytes.
 */
static asm_instr_reg *get_gp_reg(
    asm_instr_context *ctx, unsigned int regnum, char *regname)
{
    assert(regnum < 16);
    snprintf(regname, 4, "%s", reg_names[regnum]);
    return &asm_instr_ctx_reg_bynum(ctx, regnum);
}

/**
 * Handle ldr-like instruction, with writeback and post-indexing
 */
static char *handle_ldr(
    asm_instr_context *ctx, unsigned int reg, int offset, uintptr_t data_addr,
    void *data, size_t datalen, unsigned int size, bool writeback, bool postindex, void *pvalue)
{
    uintptr_t address;
    char sz_reg[4], *sz_operand;

    sz_operand = malloc(sizeof("[rXX=0x, 0x]!") + 8 + 8);
    assert(sz_operand);

    address = *get_gp_reg(ctx, reg, sz_reg);
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
        fprintf(stderr, "Error: mem parameter '%s' does not use address %#" PRIxPTR "\n",
                sz_operand, data_addr);
        free(sz_operand);
        return NULL;
    }

    /* Copy the real data */
    if (datalen >= size) {
        memcpy(pvalue, data, size);
    } else {
        /* It may go past the actual data */
        memset(pvalue, 0, size);
        memcpy(pvalue, data, datalen);
    }

    if (postindex) {
        assert(!writeback); /* post-index and writeback bits are exclusive */
        asm_instr_ctx_reg_bynum(ctx, reg) = address + offset;
    } else if (writeback) {
        asm_instr_ctx_reg_bynum(ctx, reg) = address;
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
    uint32_t instr = *(uint32_t *)(R_PC(ctx));
    asm_instr_reg cpsr = R_CPSR(ctx);
    bool is_ok;
    size_t copy_size;
    unsigned int reg_d, reg_n;
    int32_t offset;
    char *sz_ldr_op, *sz_reglist, *sz_reglist_end;
    unsigned int count_reglist, idx;
    uintptr_t address;

    /* Detect Thumb mode early */
    if (cpsr & ARM_CPSR_T) {
        /* TODO Add Thumb mode */
        fprintf(stderr, "Thumb mode not yet implemented @%" PRIxREG ": %x\n",
            R_PC(ctx), instr);
        return false;
    }

    /* Evaluate the condition flags.
     * They should be verified, otherwise the instruction would have been skipped over.
     */
    is_ok = false;
    switch ((instr >> 28) & 15) {
        case 0:
            /* EQ, equal */
            is_ok = !!(cpsr & ARM_CPSR_Z);
            break;
        case 1:
            /* NE, not equal */
            is_ok = !(cpsr & ARM_CPSR_Z);
            break;
        case 2:
            /* CS, carry set or HS, unsigned higher or same */
            is_ok = !!(cpsr & ARM_CPSR_C);
            break;
        case 3:
            /* CC, carry clear  or LO, unsigned lower */
            is_ok = !(cpsr & ARM_CPSR_C);
            break;
        case 4:
            /* MI, minus, negative */
            is_ok = !!(cpsr & ARM_CPSR_N);
            break;
        case 5:
            /* PL, plus, positive or zero */
            is_ok = !(cpsr & ARM_CPSR_N);
            break;
        case 6:
            /* VS, overflow set */
            is_ok = !!(cpsr & ARM_CPSR_V);
            break;
        case 7:
            /* VC, overflow clear */
            is_ok = !(cpsr & ARM_CPSR_V);
            break;
        case 8:
            /* HI, unsigned higher */
            is_ok = !!(cpsr & ARM_CPSR_C) && !(cpsr & ARM_CPSR_Z);
            break;
        case 9:
            /* LS, unsigned lower or same */
            is_ok = !(cpsr & ARM_CPSR_C) || !!(cpsr & ARM_CPSR_Z);
            break;
        case 10:
            /* GE, signed greater than or equal */
            is_ok = (!(cpsr & ARM_CPSR_N)) == (!(cpsr & ARM_CPSR_V));
            break;
        case 11:
            /* LT, signed less than */
            is_ok = (!(cpsr & ARM_CPSR_N)) != (!(cpsr & ARM_CPSR_V));
            break;
        case 12:
            /* GT, signed greater than */
            is_ok = (!(cpsr & ARM_CPSR_N)) == (!(cpsr & ARM_CPSR_V)) && !(cpsr & ARM_CPSR_Z);
            break;
        case 13:
            /* LE, signed less than or equal */
            is_ok = (!(cpsr & ARM_CPSR_N)) != (!(cpsr & ARM_CPSR_V)) || !!(cpsr & ARM_CPSR_Z);
            break;
        case 14:
            /* AL, always */
            is_ok = true;
            break;
        case 15:
            /* NV, never */
            is_ok = false;
    }
    if (!is_ok) {
        fprintf(stderr, "Invalid condition for ARM instruction @%" PRIxREG ": %x, CPSR = %" PRIxREG "\n",
                R_PC(ctx), instr, cpsr);
        return false;
    }

    /* LDR/STR/LDRB/STRB Rd, Rn: single data transfer
     *   31..28: condition
     *   27..26: 01
     *       25: I = 0 for immediate offset, 1 for shifted register
     *       24: P = 0 for post (add offset after transfer), 1 for pre (before)
     *       23: U = 0 for down (subtract offset from base), 1 for up (add)
     *       22: B = 0 for word transfer, 1 for byte
     *       21: W = 0 for no write-back, 1 to write address into base
     *       20: L = 0 to store (STR), 1 to load (LDR)
     *   19..16: Rn, base register
     *   15..12: Rd, source/destination register
     *   11.. 0: offset if I = 0
     *   11.. 4: shift if I = 1
     *    3.. 0: Rm, offset register if I = 1
     */
#define ARM_LDR_I_MASK 0x02000000
#define ARM_LDR_P_MASK 0x01000000
#define ARM_LDR_U_MASK 0x00800000
#define ARM_LDR_B_MASK 0x00400000
#define ARM_LDR_W_MASK 0x00200000
    if ((instr & 0x0c100000) == 0x04100000) {
        reg_n = (instr >> 16) & 15;
        reg_d = (instr >> 12) & 15;

        if (instr & ARM_LDR_I_MASK) {
            fprintf(stderr, "LDR with shifted register not yet implemented.\n");
            return false;
        } else {
            /* Read immediate offset */
            offset = (int)(instr & 0xfff);
        }
        if (!(instr & ARM_LDR_U_MASK)) {
            offset = -offset;
        }
        sz_ldr_op = handle_ldr(
            ctx, reg_n, offset, data_addr, data, datalen,
            (instr & ARM_LDR_B_MASK) ? 1 : 4,
            (instr & ARM_LDR_W_MASK),
            !(instr & ARM_LDR_P_MASK),
            &asm_instr_ctx_reg_bynum(ctx, reg_d));
        if (!sz_ldr_op) {
            return false;
        }
        if (instr & ARM_LDR_B_MASK) {
            /* Keep only one byte in the register */
            asm_instr_ctx_reg_bynum(ctx, reg_d) &= 0xff;
        }
        asm_printf(asm_instr, "ldr%s %s, %s",
            (instr & ARM_LDR_B_MASK) ? "b" : "", reg_names[reg_d], sz_ldr_op);
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }
#undef ARM_LDR_I_MASK
#undef ARM_LDR_P_MASK
#undef ARM_LDR_U_MASK
#undef ARM_LDR_B_MASK
#undef ARM_LDR_W_MASK

    /* LDRH/STRH/LDRSB/LDRSH Rd, Rn, #: halfword and signed data transfer
     *   31..28: condition
     *   27..25: 000
     *       24: P = 0 for post (add offset after transfer), 1 for pre (before)
     *       23: U = 0 for down (subtract offset from base), 1 for up (add)
     *       22: I = 1 for immediate offset, 0 for shifted register
     *       21: W = 0 for no write-back, 1 to write address into base
     *       20: L = 0 to store (STR), 1 to load (LDR)
     *   19..16: Rn, base register
     *   15..12: Rd, source/destination register
     *   11.. 8: high nibble of offset if I = 0, 0000 if I = 1
     *        7: 1
     *    6.. 5: SH = 00 for SWP, 01 for unsigned halfword, 10 for signed byte, 11 for unsigned byte
     *        4: 1
     *    3.. 0: low nibble of offset if I = 0, Rm, offset register if I = 1
     */
#define ARM_LDRH_P_MASK 0x01000000
#define ARM_LDRH_U_MASK 0x00800000
#define ARM_LDRH_I_MASK 0x00400000
#define ARM_LDRH_W_MASK 0x00200000
#define ARM_LDRH_L_MASK 0x00100000
#define ARM_LDRH_S_MASK 0x00000040
#define ARM_LDRH_H_MASK 0x00000020
#define ARM_LDRH_SH_MASK (ARM_LDRH_S_MASK | ARM_LDRH_H_MASK)
    if ((instr & 0x0e100090) == 0x00100090 && (instr & ARM_LDRH_SH_MASK)) {
        copy_size = (instr & ARM_LDRH_H_MASK) ? 2 : 1;
        reg_n = (instr >> 16) & 15;
        reg_d = (instr >> 12) & 15;

        if (!(instr & ARM_LDRH_I_MASK)) {
            fprintf(stderr, "LDRH with shifted register not yet implemented.\n");
            return false;
        } else {
            /* Read immediate offset */
            offset = (int32_t)(((instr & 0xf00) >> 4) | (instr & 0xf));
        }
        if (!(instr & ARM_LDRH_U_MASK)) {
            offset = -offset;
        }

        sz_ldr_op = handle_ldr(
            ctx, reg_n, offset, data_addr, data, datalen, copy_size,
            (instr & ARM_LDRH_W_MASK),
            !(instr & ARM_LDRH_P_MASK),
            &asm_instr_ctx_reg_bynum(ctx, reg_d));
        if (!sz_ldr_op) {
            return false;
        }
        if (!(instr & ARM_LDRH_S_MASK)) { /* LDRH */
            asm_printf(asm_instr, "ldrh %s, %s", reg_names[reg_d], sz_ldr_op);
        } else if (!(instr & ARM_LDRH_H_MASK)) { /* LDRSB */
            asm_printf(asm_instr, "ldrsb %s, %s", reg_names[reg_d], sz_ldr_op);
            /* Sign-extend the result */
            if (asm_instr_ctx_reg_bynum(ctx, reg_d) & 0x80) {
                asm_instr_ctx_reg_bynum(ctx, reg_d) |= 0xffffff00;
            }
        } else { /* LDRSH */
            asm_printf(asm_instr, "ldrsh %s, %s", reg_names[reg_d], sz_ldr_op);
            /* Sign-extend the result */
            if (asm_instr_ctx_reg_bynum(ctx, reg_d) & 0x8000) {
                asm_instr_ctx_reg_bynum(ctx, reg_d) |= 0xffff0000;
            }
        }
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }
#undef ARM_LDRH_P_MASK
#undef ARM_LDRH_U_MASK
#undef ARM_LDRH_I_MASK
#undef ARM_LDRH_W_MASK
#undef ARM_LDRH_L_MASK
#undef ARM_LDRH_S_MASK
#undef ARM_LDRH_H_MASK
#undef ARM_LDRH_SH_MASK

    /* LDRD for ARMv5TE, ARMv6 and ARMv7: load register dual
     *   31..28: condition
     *   27..25: 000
     *       24: P = 0 for post (add offset after transfer), 1 for pre (before)
     *       23: U = 0 for down (subtract offset from base), 1 for up (add)
     *       22: ?
     *       21: W = 0 for no write-back, 1 to write address into base
     *       20: 0
     *   19..16: Rn, base register
     *   15..12: Rt, target register (Rt and Rt+1)
     *   11.. 4: 00001101 for LDRD (00001011 for STRD)
     *    3.. 0: Rm, offset register
     */
#define ARM_LDRD_P_MASK 0x01000000
#define ARM_LDRD_U_MASK 0x00800000
#define ARM_LDRD_W_MASK 0x00200000
    if ((instr & 0x0e100ff0) == 0x000000d0) {
        reg_n = (instr >> 16) & 15;
        reg_d = (instr >> 12) & 15;
        if (reg_d >= 14) {
            fprintf(stderr, "Error: illegal LDRD instruction with PC");
            return false;
        }
        offset = (int)(instr & 0xf);
        if (!(instr & ARM_LDRD_U_MASK)) {
            offset = -offset;
        }
        sz_ldr_op = handle_ldr(
            ctx, reg_n, offset, data_addr, data, datalen, 8,
            (instr & ARM_LDRD_W_MASK),
            !(instr & ARM_LDRD_P_MASK),
            &asm_instr_ctx_reg_bynum(ctx, reg_d));
        if (!sz_ldr_op) {
            return false;
        }
        asm_printf(asm_instr, "ldrd %s, %s, %s",
            reg_names[reg_d], reg_names[reg_d + 1], sz_ldr_op);
        free(sz_ldr_op);
        R_PC(ctx) += 4;
        return true;
    }
#undef ARM_LDRD_P_MASK
#undef ARM_LDRD_U_MASK
#undef ARM_LDRD_W_MASK

    /* LDM Rn, {Rd, ...}: Load multiple
     *   31..28: condition
     *   27..25: 100
     *       24: P = 0 for post (add offset after transfer), 1 for pre (before)
     *       23: U = 0 for down (subtract offset from base), 1 for up (add)
     *       22: S = 1 for load PSR or force user mode
     *       21: W = 0 for no write-back, 1 to write address into base
     *       20: L = 0 to store (STR), 1 to load (LDR)
     *   19..16: Rn, base register
     *   15.. 0: register list
     *
     * When writeback is enabled:
     *      L P U  mnemonic if on stack  mnemonic otherwise
     *      1 1 1   LDMED                   LDMIB           (pre-increment load)
     *      1 0 1   LDMFD                   LDMIA           (post-increment load)
     *      1 1 0   LDMEA                   LDMDB           (pre-decrement load)
     *      1 0 0   LDMFA                   LDMDA           (post-decrement load)
     *      0 1 1   STMFA                   STMIB           (pre-increment store)
     *      0 0 1   STMEA                   STMIA           (post-increment store)
     *      0 1 0   STMFD                   STMDB           (pre-decrement store)
     *      0 0 0   STMED                   STMDA           (post-decrement store)
     *
     * (F = Full stack, E = Empty stack, A = Ascending, D = Descending)
     * (I = Increment, D = Decrement, B = Before, A = After)
     */
#define ARM_LDM_P_MASK 0x01000000
#define ARM_LDM_U_MASK 0x00800000
#define ARM_LDM_S_MASK 0x00400000
#define ARM_LDM_W_MASK 0x00200000
#define ARM_LDM_L_MASK 0x00100000
    if ((instr & 0x0e100000) == 0x08100000) {
        if (!(instr & ARM_LDM_U_MASK)) {
            fprintf(stderr, "LDM with decrement not yet implemented.\n");
            return false;
        }
        if (instr & ARM_LDM_P_MASK) {
            fprintf(stderr, "LDM with pre-increment not yet implemented.\n");
            return false;
        }
        reg_n = (instr >> 16) & 15;

        sz_reglist = malloc(4 * 16);
        if (!sz_reglist) {
            return false;
        }

        /* Check the address, using sz_reglist as trash space */
        address = *get_gp_reg(ctx, reg_n, sz_reglist);
        if (address != data_addr) {
            fprintf(stderr, "Error: mem parameter '%s' does not use address %#" PRIxPTR "\n",
                    sz_reglist, data_addr);
            free(sz_reglist);
            return false;
        }

        count_reglist = 0;
        sz_reglist_end = sz_reglist;
        for (idx = 0; idx < 16; idx++) {
            if (!(instr & (1 << idx)))
                continue;

            /* Load data */
            if (datalen >= 4) {
                memcpy(&asm_instr_ctx_reg_bynum(ctx, idx), data, 4);
                datalen -= 4;
            } else {
                asm_instr_ctx_reg_bynum(ctx, idx) = 0;
                memcpy(&asm_instr_ctx_reg_bynum(ctx, idx), data, datalen);
                datalen = 0;
            }
            data += 4;
            address += 4;

            /* Add the register to the list */
            if (!count_reglist) {
                sz_reglist_end += sprintf(sz_reglist_end, "%s", reg_names[idx]);
            } else {
                sz_reglist_end += sprintf(sz_reglist_end, ", %s", reg_names[idx]);
            }
            count_reglist += 1;
        }
        if (!count_reglist) {
            free(sz_reglist);
            return false;
        }

        if (instr & ARM_LDM_W_MASK) {
            asm_instr_ctx_reg_bynum(ctx, reg_n) = address;
            asm_printf(asm_instr, "ldm %s=%#" PRIxPTR "!, {%s}",
                       reg_names[reg_n], data_addr, sz_reglist);
        } else {
            asm_printf(asm_instr, "ldm %s=%#" PRIxPTR ", {%s}",
                       reg_names[reg_n], data_addr, sz_reglist);
        }
        free(sz_reglist);
        R_PC(ctx) += 4;
        return true;
    }
#undef ARM_LDM_P_MASK
#undef ARM_LDM_U_MASK
#undef ARM_LDM_S_MASK
#undef ARM_LDM_W_MASK
#undef ARM_LDM_L_MASK

    fprintf(stderr, "Unknown ARM instruction @%" PRIxREG ": %x\n",
            R_PC(ctx), instr);
    return false;
}
