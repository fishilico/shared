/**
 * x86_64 instruction set decoder
 *
 * Documentation:
 * http://developer.amd.com/resources/documentation-articles/developer-guides-manuals/
 * AMD64 Architecture Programmer's Manual Volume 1: Application Programming
 * AMD64 Architecture Programmer's Manual Volume 2: System Programming
 * AMD64 Architecture Programmer's Manual Volume 3: General Purpose and System Instructions
 * AMD64 Architecture Programmer's Manual Volume 4: 128-bit and 256 bit media instructions
 * AMD64 Architecture Programmer's Manual Volume 5: 64-Bit Media and x87 Floating-Point Instructions
 *
 * http://ref.x86asm.net/coder64.html X86 Opcode and Instruction Reference
 */
#include "arch_x86_64.h"

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
 * If regname is not null, write the register name to it.  Its size must be at least 5 bytes.
 */
static asm_instr_reg *get_gp_reg(
    asm_instr_context *ctx, unsigned int regnum, unsigned int bitsize, char *regname)
{
    const char *regs8[8] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
    const char *regs16[8] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };

    assert(regnum < 16);
    assert(bitsize == 8 || bitsize == 16 || bitsize == 32 || bitsize == 64);

    if (regname) {
        if (regnum < 8) {
            if (bitsize == 8) {
                snprintf(regname, 3, "%s", regs8[regnum]);
                if (regnum > 4) {
                    /* ah, ch, dh, bh are not yet supported */
                    fprintf(stderr, "warning: 8-bit registers not yet fully supported\n");
                    regnum &= 3;
                }
            } else if (bitsize == 16) {
                snprintf(regname, 3, "%s", regs16[regnum]);
            } else if (bitsize == 32) {
                snprintf(regname, 4, "e%s", regs16[regnum]);
            } else if (bitsize == 64) {
                snprintf(regname, 4, "r%s", regs16[regnum]);
            } else {
                abort(); /* unreachable */
            }
        } else {
            /* r8..r15 */
            if (bitsize == 8) {
                snprintf(regname, 5, "r%ub", regnum);
            } else if (bitsize == 16) {
                snprintf(regname, 5, "r%uw", regnum);
            } else if (bitsize == 32) {
                snprintf(regname, 5, "r%ud", regnum);
            } else if (bitsize == 64) {
                snprintf(regname, 4, "r%u", regnum);
            } else {
                abort(); /* unreachable */
            }
        }
    }

    switch (regnum) {
        case 0:
            return &R_RAX(ctx);
        case 1:
            return &R_RCX(ctx);
        case 2:
            return &R_RDX(ctx);
        case 3:
            return &R_RBX(ctx);
        case 4:
            return &R_RSP(ctx);
        case 5:
            return &R_RBP(ctx);
        case 6:
            return &R_RSI(ctx);
        case 7:
            return &R_RDI(ctx);
        case 8:
            return &R_R8(ctx);
        case 9:
            return &R_R9(ctx);
        case 10:
            return &R_R10(ctx);
        case 11:
            return &R_R11(ctx);
        case 12:
            return &R_R12(ctx);
        case 13:
            return &R_R13(ctx);
        case 14:
            return &R_R14(ctx);
        case 15:
            return &R_R15(ctx);
    }
    abort(); /* unreachable */
}

/**
 * Decode the ModR/M bytes at instr and return information to the caller:
 * * return value: length of the parameters
 * * op_reg: pointer to the specified register in ctx
 * * operand_reg: description of the reg parameter
 * * operand_rm: description of the reg/mem parameter
 *
 * Also check that the r/m parameter is data_addr
 */
static size_t decode_modrm_check(
    asm_instr_context *ctx, const uint8_t *instr, uint8_t rexprefix, uintptr_t data_addr,
    asm_instr_reg **op_reg, char **operand_reg, char **operand_rm)
{
    size_t paramlen = 1;
    uint8_t modrm = instr[0], sib;
    unsigned int regnum, bitsize;
    char *regname, *sibdesc = NULL, *rmdesc;
    uintptr_t computed_addr;

    /* Read the R/M part */
    if (operand_rm) {
        computed_addr = 0;

        if ((modrm & 0xc0) == 0xc0) {
            /* Mod = 11, direct register */
            fprintf(stderr, "Invalid instruction: ModR/M bit not set to memory operand\n");
            return 0;
        } else if ((modrm & 0xc7) == 5) {
            /* Mod = 00, R/M = 101 : disp32 in legacy mode, RIP+disp32 in 64-bit mode */
            if (rexprefix & X86_64_REX_W) {
                fprintf(stderr, "Invalid instruction: ModR/M bit not set to RIP+disp32\n");
            } else {
                fprintf(stderr, "Invalid instruction: ModR/M bit not set to disp32\n");
            }
            return 0;
        } else if ((modrm & 7) == 4) {
            /* R/M = 100 : Scale, Index, Base */
            char index_reg[5], base_reg[5];
            unsigned int scale;

            sib = instr[1];
            paramlen += 1;

            if ((sib & 7) == 5) {
                if ((modrm & 0xc0) == 0) {
                    /* Mod = 00, base = 101: disp32 with index */
                    fprintf(stderr, "Invalid instruction: ModR/M and SIB set to disp32+index\n");
                    return 0;
                } else if ((modrm & 0xc0) == 0x40) {
                    /* Mod = 01, base = 101: [rBP]+disp8 with index: fall through */
                } else if ((modrm & 0xc0) == 0x80) {
                    /* Mod = 10, base = 101: [rBP]+disp32 with index: fall through */
                } else {
                    abort(); /* unreachable */
                }
            }

            if ((sib & 0x38) == 0x20) {
                /* index = 100: no index */
                sibdesc = malloc(5);
                assert(sibdesc);
                regnum = (sib & 7) | ((rexprefix & X86_64_REX_B) ? 8 : 0);
                computed_addr = (uintptr_t)*get_gp_reg(ctx, regnum, 64, sibdesc);
            } else {
                /* Read index */
                sibdesc = malloc(sizeof("r...+8*r..."));
                assert(sibdesc);

                regnum = ((sib >> 3) & 7) | ((rexprefix & X86_64_REX_X) ? 8 : 0);
                computed_addr = (uintptr_t)*get_gp_reg(ctx, regnum, 64, index_reg);
                scale = 1 << ((sib & 0xc0) >> 6);
                computed_addr *= scale;
                regnum = (sib & 7) | ((rexprefix & X86_64_REX_B) ? 8 : 0);
                computed_addr += (uintptr_t)*get_gp_reg(ctx, regnum, 64, base_reg);

                sprintf(sibdesc, "%.4s+%u*%.4s", base_reg, scale, index_reg);
            }
        } else {
            /* Mod != 11, R/M != 100: memory given by register */
            sibdesc = malloc(5);
            assert(sibdesc);
            regnum = (modrm & 7) | ((rexprefix & X86_64_REX_B) ? 8 : 0);
            computed_addr = (uintptr_t)*get_gp_reg(ctx, regnum, 64, sibdesc);
        }

        assert(sibdesc);

        /* Decode the displacement and build operand_rm */
        if ((modrm & 0xc0) == 0) {
            /* Mod = 00: no displacement */
            rmdesc = malloc(sizeof("(=0x)") + 16 + strlen(sibdesc));
            assert(rmdesc);
            sprintf(rmdesc, "(%s=0x%" PRIxPTR ")", sibdesc, computed_addr);
        } else if ((modrm & 0xc0) == 0x40) {
            /* Mod = 01: 8-bit displacement */
            unsigned int disp = instr[paramlen];
            paramlen += 1;

            rmdesc = malloc(sizeof("-0x(=0x)") + 2 + 16 + strlen(sibdesc));
            assert(rmdesc);
            if (disp >= 0x80) {
                sprintf(rmdesc, "-0x%x(%s=0x%" PRIxPTR ")", 0x100 - disp, sibdesc, computed_addr);
                computed_addr -= 0x100 - disp;
            } else {
                sprintf(rmdesc, "0x%x(%s=0x%" PRIxPTR ")", disp, sibdesc, computed_addr);
                computed_addr += disp;
            }
        } else if ((modrm & 0xc0) == 0x80) {
            if (!(rexprefix & X86_64_REX_W)) {
                /* Mod = 10: 32-bit displacement */
                uint32_t disp;
                memcpy(&disp, &instr[paramlen], 4);
                paramlen += 4;

                rmdesc = malloc(sizeof("-0x(=0x)") + 8 + 16 + strlen(sibdesc));
                assert(rmdesc);
                if (disp >> 31) {
                    disp = 1 + ((~disp) & 0xffffffffU);
                    sprintf(rmdesc, "-0x%x(%s=0x%" PRIxPTR ")", disp, sibdesc, computed_addr);
                    computed_addr -= disp;
                } else {
                    sprintf(rmdesc, "0x%x(%s=0x%" PRIxPTR ")", disp, sibdesc, computed_addr);
                    computed_addr += disp;
                }
            } else {
                /* Mod = 10, REX.W: 64-bit displacement */
                uint64_t disp;
                memcpy(&disp, &instr[paramlen], 8);
                paramlen += 8;

                rmdesc = malloc(sizeof("-0x(=0x)") + 16 + 16 + strlen(sibdesc));
                assert(rmdesc);
                if (disp >> 31) {
                    disp = 1 + ((~disp) & 0xffffffffffffffffUL);
                    sprintf(rmdesc, "-0x%" PRIx64 "(%s=0x%" PRIxPTR ")", disp, sibdesc, computed_addr);
                    computed_addr -= disp;
                } else {
                    sprintf(rmdesc, "0x%" PRIx64 "(%s=0x%" PRIxPTR ")", disp, sibdesc, computed_addr);
                    computed_addr += disp;
                }
            }
        } else {
            abort(); /* unreachable */
        }
        free(sibdesc);

        /* Check whether the computer address matches */
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter '%s' does not use address %" PRIxPTR "\n",
                    rmdesc, data_addr);
            free(rmdesc);
            return 0;
        }
        *operand_rm = rmdesc;
    }

    /* Read the Reg part */
    if (op_reg) {
        assert(operand_reg);

        regnum = ((modrm >> 3) & 7) | ((rexprefix & X86_64_REX_R) ? 8 : 0);
        regname = malloc(5);
        assert(regname);
        bitsize = (rexprefix & X86_64_REX_FAKE_R8) ? 8 : (rexprefix & X86_64_REX_W) ? 64 : 32;
        *op_reg = get_gp_reg(ctx, regnum, bitsize, regname);
        *operand_reg = regname;
    } else {
        assert(!operand_reg);
    }
    return paramlen;
}

/**
 * Update the EFLAGS according to a 8-bit difference
 */
static asm_instr_reg update_eflags_diff8(asm_instr_reg eflags, uint8_t diff)
{
    eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
                X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);
    if (__builtin_parity(diff)) {
        eflags |= X86_EFLAGS_PF;
    }
    if (!diff) {
        eflags |= X86_EFLAGS_ZF;
    }
    if (diff & 0x80) {
        eflags |= X86_EFLAGS_SF;
    }
    return eflags;
}

/**
 * Emulate an ASM instruction in the given context, with data the pseudo content at data_addr
 */
bool run_mov_asm_instruction_p(
    asm_instr_context *ctx, uintptr_t data_addr, uint8_t *data, size_t datalen,
    char *asm_instr)
{
    size_t i, paramlen;
    const uint8_t *instr = (uint8_t *)(R_RIP(ctx));
    const uint8_t *orig_instr = instr;
    uint8_t rexprefix = 0, vexprefix;
    asm_instr_reg *op_reg = NULL, tmp_reg;
    char *operand_reg = NULL;
    char *operand_rm = NULL;
    bool has_66_prefix = false, has_f2_prefix = false, has_f3_prefix = false;
    bool has_no_prefix;
    bool has_vex128_prefix = false /*, has_vex256_prefix = false */ ;
    bool has_implicit_0f = false;

    /* Read at most 5 prefixes */
    for (i = 0; i < 4; i++) {
        if (instr[i] == 0x66) {
            /* 66: 16-bit operand size */
            has_66_prefix = true;
        } else if (instr[i] == 0xf2) {
            /* f2: repne/repnz */
            has_f2_prefix = true;
        } else if (instr[i] == 0xf3) {
            /* f3: rep/repe/repz */
            has_f3_prefix = true;
        } else {
            break;
        }
    }
    has_no_prefix = !(has_66_prefix || has_f2_prefix || has_f3_prefix);

    if ((instr[i] & 0xf0) == 0x40) {
        /* REX.W,R,X,B prefix */
        rexprefix = instr[i] & 0xf;
        i++;
    } else if (has_no_prefix && instr[0] == 0xc5) {
        /* 2-byte VEX prefix */
        vexprefix = instr[i + 1];
        rexprefix = (vexprefix & 0x80) ? 0 : X86_64_REX_R;
        if (vexprefix & 4) {
            /* has_vex256_prefix = true; */
        } else {
            has_vex128_prefix = true;
        }
        if ((vexprefix & 3) == 1) {
            has_66_prefix = true;
        } else if ((vexprefix & 3) == 2) {
            has_f3_prefix = true;
        } else if ((vexprefix & 3) == 3) {
            has_f2_prefix = true;
        }

        /* Only increment i once so that instr[i] can be considered 0x0f */
        has_implicit_0f = true;
        i++;
    }
    R_RIP(ctx) += i;
    instr = &instr[i];

    /* 0f: Escape opcode */
    if (has_implicit_0f || instr[0] == 0x0f) {
        /* f3 0f 6f /r: movdqu xmm2/mem, xmm1 */
        if (has_f3_prefix && instr[1] == 0x6f) {
            unsigned int xmmreg = ((instr[2] >> 3) & 7) | ((rexprefix & X86_64_REX_R) ? 8 : 0);
            paramlen = decode_modrm_check(ctx, instr + 2, rexprefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            if (has_vex128_prefix) {
                asm_printf(asm_instr, "vmovdqu %s, xmm%u", operand_rm, xmmreg);
                /* Should clean the upper bits of xmm register */
            } else {
                asm_printf(asm_instr, "movdqu %s, xmm%u", operand_rm, xmmreg);
            }
            free(operand_rm);
            memcpy(asm_instr_ctx_xmm_addr(ctx, xmmreg), data, 16);
            R_RIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 66 0f 3a 63 /r imm8: pcmpistri imm8, xmm2/m128, xmm1 */
        if (has_66_prefix && instr[1] == 0x3a && instr[2] == 0x63) {
            unsigned int xmmreg = ((instr[3] >> 3) & 7) | ((rexprefix & X86_64_REX_R) ? 8 : 0);
            uint8_t *xmmdst = (uint8_t *)asm_instr_ctx_xmm_addr(ctx, xmmreg);
            uint8_t pcmpistri_op;
            asm_instr_reg eflags;

            paramlen = decode_modrm_check(ctx, instr + 3, rexprefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            pcmpistri_op = instr[3 + paramlen];
            asm_printf(asm_instr, "pcmpistri 0x%x, %s, xmm%u", pcmpistri_op, operand_rm, xmmreg);
            free(operand_rm);
            if (pcmpistri_op == 8) {
                /* Equal Each, 16 unsigned bytes, Positive Polarity */
                eflags = R_EFL(ctx);
                eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
                            X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF);
                if (xmmdst[0] != data[0]) {
                    eflags |= X86_EFLAGS_OF;
                }
                for (i = 0; i < 16; i++) {
                    if (xmmdst[i] == data[i] && !(eflags & X86_EFLAGS_CF)) {
                        R_RCX(ctx) = (asm_instr_reg)i;
                        eflags |= X86_EFLAGS_CF;
                    }
                    if (!data[i]) {
                        eflags |= X86_EFLAGS_ZF;
                    }
                    if (!xmmdst[i]) {
                        eflags |= X86_EFLAGS_SF;
                    }
                }
                if (!(eflags & X86_EFLAGS_CF)) {
                    R_RCX(ctx) = 16;
                }
                R_EFL(ctx) = eflags;
            } else {
                fprintf(stderr, "Error: pcmpistri operation 0x%x not implemented\n", pcmpistri_op);
                return false;
            }
            R_RIP(ctx) += 4 + paramlen;
            return true;
        }

        /* 66 0f 74 /r: pcmpeqb xmm2/mem, xmm1 ; compare bytes and set 0xff if equal, 0 if not */
        if (has_66_prefix && instr[1] == 0x74) {
            unsigned int xmmreg = ((instr[2] >> 3) & 7) | ((rexprefix & X86_64_REX_R) ? 8 : 0);
            uint8_t *xmmdst = (uint8_t *)asm_instr_ctx_xmm_addr(ctx, xmmreg);

            paramlen = decode_modrm_check(ctx, instr + 2, rexprefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "pcmpeqb %s, xmm%u", operand_rm, xmmreg);
            free(operand_rm);
            for (i = 0; i < 16; i++) {
                xmmdst[i] = (xmmdst[i] == data[i]) ? 0xff : 0;
            }
            R_RIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 0f 10 /r: movups xmm2/mem, xmm1 */
        if (has_no_prefix && instr[1] == 0x10) {
            unsigned int xmmreg = ((instr[2] >> 3) & 7) | ((rexprefix & X86_64_REX_R) ? 8 : 0);

            paramlen = decode_modrm_check(ctx, instr + 2, rexprefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movups %s, xmm%u", operand_rm, xmmreg);
            free(operand_rm);
            memcpy(asm_instr_ctx_xmm_addr(ctx, xmmreg), data, 16);
            R_RIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 0f b6 /r: movzbl reg/mem8, reg */
        if (has_no_prefix && instr[1] == 0xb6) {
            paramlen = decode_modrm_check(ctx, instr + 2, rexprefix, data_addr, &op_reg, &operand_reg, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movzbl %s, %s", operand_rm, operand_reg);
            free(operand_rm);
            free(operand_reg);
            *op_reg = 0;
            memcpy(op_reg, data, 1);
            R_RIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 0f b7 /r: movzwl reg/mem16, reg */
        if (has_no_prefix && instr[1] == 0xb7) {
            paramlen = decode_modrm_check(ctx, instr + 2, rexprefix, data_addr, &op_reg, &operand_reg, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movzwl %s, %s", operand_rm, operand_reg);
            free(operand_rm);
            free(operand_reg);
            *op_reg = 0;
            memcpy(op_reg, data, 2);
            R_RIP(ctx) += 2 + paramlen;
            return true;
        }
    }

    /* 33 /r: xor reg/mem, reg */
    if (instr[0] == 0x33) {
        paramlen = decode_modrm_check(ctx, instr + 1, rexprefix, data_addr, &op_reg, &operand_reg, &operand_rm);
        if (!paramlen) {
            return false;
        }
        asm_printf(asm_instr, "xor %s, %s", operand_rm, operand_reg);
        free(operand_rm);
        free(operand_reg);
        if (rexprefix & X86_64_REX_W) {
            memcpy(&tmp_reg, data, 8);
        } else {
            tmp_reg = 0;
            memcpy(&tmp_reg, data, 4);
        }
        *op_reg ^= tmp_reg;
        R_RIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 38 /r: cmpb reg8, reg/mem8 */
    if (instr[0] == 0x38) {
        paramlen = decode_modrm_check(ctx, instr + 1, rexprefix | X86_64_REX_FAKE_R8,
                                      data_addr, &op_reg, &operand_reg, &operand_rm);
        if (!paramlen) {
            return false;
        }
        asm_printf(asm_instr, "cmp %s, %s", operand_reg, operand_rm);
        free(operand_rm);
        free(operand_reg);
        R_EFL(ctx) = update_eflags_diff8(R_EFL(ctx), (uint8_t)(data[0] - *op_reg));
        R_RIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 3a /r: cmpb reg/mem8, reg8 */
    if (instr[0] == 0x3a) {
        paramlen = decode_modrm_check(ctx, instr + 1, rexprefix | X86_64_REX_FAKE_R8,
                                      data_addr, &op_reg, &operand_reg, &operand_rm);
        if (!paramlen) {
            return false;
        }
        asm_printf(asm_instr, "cmp %s, %s", operand_rm, operand_reg);
        free(operand_rm);
        free(operand_reg);
        R_EFL(ctx) = update_eflags_diff8(R_EFL(ctx), (uint8_t)(*op_reg - data[0]));
        R_RIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 8a /r: mov reg/mem8, reg8 */
    if (instr[0] == 0x8a) {
        paramlen = decode_modrm_check(ctx, instr + 1, rexprefix, data_addr, NULL, NULL, &operand_rm);
        if (!paramlen) {
            return false;
        }
        operand_reg = malloc(5);
        assert(operand_reg);
        op_reg = get_gp_reg(ctx, ((instr[1] >> 3) & 7), 8, operand_reg);
        asm_printf(asm_instr, "mov %s, %s", operand_rm, operand_reg);
        free(operand_rm);
        free(operand_reg);
        *(uint8_t *)op_reg = data[0];
        R_RIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 8b /r: mov reg/mem, reg */
    if (instr[0] == 0x8b) {
        paramlen = decode_modrm_check(ctx, instr + 1, rexprefix, data_addr, &op_reg, &operand_reg, &operand_rm);
        if (!paramlen) {
            return false;
        }
        asm_printf(asm_instr, "mov %s, %s", operand_rm, operand_reg);
        free(operand_rm);
        free(operand_reg);
        if (rexprefix & X86_64_REX_W) {
            memcpy(op_reg, data, 8);
        } else {
            *op_reg = 0;
            memcpy(op_reg, data, 4);
        }
        R_RIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 80 /7 ib: cmpb imm8, reg/mem8 */
    if (instr[0] == 0x80 && (instr[1] & 0x38) == 0x38) {
        int8_t op1 = (int8_t)data[0], op2 = 0;

        paramlen = decode_modrm_check(ctx, instr + 1, rexprefix, data_addr, NULL, NULL, &operand_rm);
        if (!paramlen) {
            return false;
        }
        op2 = (int8_t)instr[1 + paramlen];
        asm_printf(asm_instr, "cmpb 0x%02x, %s", op2, operand_rm);
        free(operand_rm);
        R_EFL(ctx) = update_eflags_diff8(R_EFL(ctx), (uint8_t)(op1 - op2));
        R_RIP(ctx) += 2 + paramlen;
        return true;
    }

    /* a4: movsb  %ds:(%rsi), %es:(%rdi) */
    if (has_no_prefix && instr[0] == 0xa4) {
        uintptr_t source_addr = (uintptr_t)R_RSI(ctx);
        if (source_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter rsi is not address %" PRIxPTR "\n", data_addr);
            return false;
        }
        asm_printf(asm_instr, "movsb (rsi=0x%" PRIxREG "), (rdi)", R_RSI(ctx));
        memcpy((uint8_t *)(uint64_t)R_RDI(ctx), data, 1);
        R_RDI(ctx) += 1;
        R_RSI(ctx) += 1;
        R_RIP(ctx) += 1;
        return true;
    }

    /* f3 48 a5: rep movsq %ds:(%rsi), %es:(%rdi) */
    if (has_f3_prefix && instr[0] == 0xa5) {
        uintptr_t source_addr = (uintptr_t)R_RSI(ctx);
        size_t rep_count = (size_t)(R_RCX(ctx) + 1);
        if (source_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter rsi is not address %" PRIxPTR "\n", data_addr);
            return false;
        }
        if (rexprefix & X86_64_REX_W) {
            asm_printf(asm_instr, "req movsq (rsi=0x%" PRIxREG "), (rdi)", R_RSI(ctx));
            rep_count *= 8;
        } else {
            asm_printf(asm_instr, "req movsw (rsi=0x%" PRIxREG "), (rdi)", R_RSI(ctx));
            rep_count *= 4;
        }
        memcpy((uint8_t *)(uint64_t)R_RDI(ctx), data, rep_count);
        R_RDI(ctx) += 1;
        R_RSI(ctx) += 1;
        R_RCX(ctx) = 0;
        R_RIP(ctx) += 1;
        return true;
    }

    /* f2 ae: repnz scas %es:(%rdi), %al */
    if (has_f2_prefix && instr[0] == 0xae) {
        uint8_t al = R_RAX(ctx) & 0xff;
        uintptr_t computed_addr = (uintptr_t)R_RDI(ctx);
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter rdi is not address %" PRIxPTR "\n", data_addr);
            return false;
        }
        for (i = 0; i < datalen && data[i] != al && R_RCX(ctx); i++) {
            R_RCX(ctx) -= 1;
        }
        assert(i < datalen);
        asm_printf(asm_instr, "repnz scas (rdi=0x%" PRIxREG "), al=0x%02x", R_RDI(ctx), al);
        R_RDI(ctx) += i;
        R_RIP(ctx) += 1;
        R_RCX(ctx) -= 1;
        return true;
    }

    instr = orig_instr;
    fprintf(stderr, "Unknown x86_64 instruction @%p: %02x %02x %02x %02x %02x %02x\n",
            (const void *)instr, instr[0], instr[1], instr[2], instr[3], instr[4], instr[5]);
    return false;
}
