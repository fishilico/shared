/**
 * x86 instruction set decoder
 *
 * Documentation:
 * http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html
 * Intel Architectures Software Developer's Manual Volume 1: Basic Architecture
 * Intel Architectures Software Developer's Manual Volume 2: Instruction Set Reference
 * Intel Architectures Software Developer's Manual Volume 3: System Programming Guide
 *
 * http://ref.x86asm.net/coder32.html X86 Opcode and Instruction Reference
 */
#include "arch_x86_32.h"

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
    const char *regs8[8] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
    const char *regs16[8] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
    asm_instr_reg *base_register;

    assert(regnum < 8);
    assert(bitsize == 8 || bitsize == 16 || bitsize == 32);

    if (regname) {
        if (bitsize == 8) {
            snprintf(regname, 4, "%s", regs8[regnum]);
            if (regnum >= 4) {
                /* ah, ch, dh, bh use unaligned addresses so require special handling */
                switch (regnum) {
                    case 4:
                        base_register = &R_EAX(ctx);
                        break;
                    case 5:
                        base_register = &R_ECX(ctx);
                        break;
                    case 6:
                        base_register = &R_EDX(ctx);
                        break;
                    case 7:
                        base_register = &R_EBX(ctx);
                        break;
                    default:
                        abort(); /* unreachable */
                }
                return (asm_instr_reg *)(void *)(((uint8_t *)base_register) + 1);
            }
        } else if (bitsize == 16) {
            snprintf(regname, 4, "%s", regs16[regnum]);
        } else if (bitsize == 32) {
            snprintf(regname, 4, "e%s", regs16[regnum]);
        } else {
            abort(); /* unreachable */
        }
    }

    switch (regnum) {
        case 0:
            return &R_EAX(ctx);
        case 1:
            return &R_ECX(ctx);
        case 2:
            return &R_EDX(ctx);
        case 3:
            return &R_EBX(ctx);
        case 4:
            return &R_ESP(ctx);
        case 5:
            return &R_EBP(ctx);
        case 6:
            return &R_ESI(ctx);
        case 7:
            return &R_EDI(ctx);
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
    asm_instr_context *ctx, const uint8_t *instr, uint8_t has_66_prefix, uintptr_t data_addr,
    asm_instr_reg **op_reg, char **operand_reg, char **operand_rm)
{
    size_t paramlen = 1;
    uint8_t modrm = instr[0], sib;
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
            /* Mod = 00, R/M = 101 : disp32 */
            fprintf(stderr, "Invalid instruction: ModR/M bit not set to disp32\n");
            return 0;
        } else if ((modrm & 7) == 4) {
            /* R/M = 100 : Scale, Index, Base */
            char index_reg[5], base_reg[5];
            unsigned int scale;

            sib = instr[1];
            paramlen += 1;

            if ((sib & 7) == 5) {
                if ((modrm & 0xc0) == 0) {
                    /* Mod = 00, base = 101: disp32[index] */
                    fprintf(stderr, "Invalid instruction: ModR/M and SIB set to disp32[index]\n");
                    return 0;
                } else if ((modrm & 0xc0) == 0x40) {
                    /* Mod = 01, base = 101: disp8[EBP][index] */
                    fprintf(stderr, "Invalid instruction: ModR/M and SIB set to disp8[EBP][index]\n");
                    return 0;
                } else if ((modrm & 0xc0) == 0x80) {
                    /* Mod = 10, base = 101: disp32[EBP][index] */
                    fprintf(stderr, "Invalid instruction: ModR/M and SIB set to disp32[EBP][index]\n");
                    return 0;
                } else {
                    abort(); /* unreachable */
                }
            }

            if ((sib & 0x38) == 0x20) {
                /* index = 100: no index */
                sibdesc = malloc(5);
                assert(sibdesc);
                computed_addr = (uintptr_t)*get_gp_reg(ctx, (sib & 7), 32, sibdesc);
            } else {
                /* Read index */
                sibdesc = malloc(sizeof("r...+8*r..."));
                assert(sibdesc);

                computed_addr = (uintptr_t)*get_gp_reg(ctx, ((sib >> 3) & 7), 32, index_reg);
                scale = 1 << ((sib & 0xc0) >> 6);
                computed_addr *= scale;
                computed_addr += (uintptr_t)*get_gp_reg(ctx, (sib & 7), 32, base_reg);
                sprintf(sibdesc, "%.4s+%u*%.4s", base_reg, scale, index_reg);
            }
        } else {
            /* Mod != 11, R/M != 100: memory given by register */
            sibdesc = malloc(5);
            assert(sibdesc);
            computed_addr = (uintptr_t)*get_gp_reg(ctx, (modrm & 7), 32, sibdesc);
        }

        assert(sibdesc);

        /* Decode the displacement and build operand_rm */
        if ((modrm & 0xc0) == 0) {
            /* Mod = 00: no displacement */
            rmdesc = malloc(sizeof("(=0x)") + 8 + strlen(sibdesc));
            assert(rmdesc);
            sprintf(rmdesc, "(%s=0x%" PRIxPTR ")", sibdesc, computed_addr);
        } else if ((modrm & 0xc0) == 0x40) {
            /* Mod = 01: 8-bit displacement */
            unsigned int disp = instr[paramlen];
            paramlen += 1;

            rmdesc = malloc(sizeof("-0x(=0x)") + 2 + 8 + strlen(sibdesc));
            assert(rmdesc);
            if (disp >= 0x80) {
                sprintf(rmdesc, "-0x%x(%s=0x%" PRIxPTR ")", 0x100 - disp, sibdesc, computed_addr);
                computed_addr -= 0x100 - disp;
            } else {
                sprintf(rmdesc, "0x%x(%s=0x%" PRIxPTR ")", disp, sibdesc, computed_addr);
                computed_addr += disp;
            }
        } else if ((modrm & 0xc0) == 0x80) {
            /* Mod = 10: 32-bit displacement */
            uint32_t disp;
            memcpy(&disp, &instr[paramlen], 4);
            paramlen += 4;

            rmdesc = malloc(sizeof("-0x(=0x)") + 8 + 8 + strlen(sibdesc));
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

        regname = malloc(5);
        assert(regname);
        *op_reg = get_gp_reg(ctx, ((modrm >> 3) & 7), (has_66_prefix ? 16 : 32), regname);
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
    const uint8_t *instr = (uint8_t *)(R_EIP(ctx));
    const uint8_t *orig_instr = instr;
    asm_instr_reg *op_reg = NULL;
    char *operand_reg = NULL;
    char *operand_rm = NULL;
    bool has_66_prefix = false, has_f2_prefix = false, has_f3_prefix = false;
    bool has_no_prefix;

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
    R_EIP(ctx) += i;
    instr = &instr[i];

    if (instr[0] == 0x0f) {
        /* f3 0f 6f /r: movdqu xmm2/mem, xmm1 */
        if (has_f3_prefix && instr[1] == 0x6f) {
            unsigned int xmmreg = (instr[2] >> 3) & 7;
            paramlen = decode_modrm_check(ctx, instr + 2, has_66_prefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movdqu %s, xmm%u", operand_rm, xmmreg);
            free(operand_rm);
            memcpy(asm_instr_ctx_xmm_addr(ctx, xmmreg), data, 16);
            R_EIP(ctx) += 2 + paramlen;
            return true;
        }

        /* f3 0f 7e /r: movq xmm2/mem, xmm1 */
        if (has_f3_prefix && instr[1] == 0x7e) {
            unsigned int xmmreg = (instr[2] >> 3) & 7;
            paramlen = decode_modrm_check(ctx, instr + 2, has_66_prefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movq %s, xmm%u", operand_rm, xmmreg);
            free(operand_rm);
            memcpy(asm_instr_ctx_xmm_addr(ctx, xmmreg), data, 8);
            R_EIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 66 0f 74 /r: pcmpeqb xmm2/mem, xmm1 ; compare bytes and set 0xff if equal, 0 if not */
        if (has_66_prefix && instr[1] == 0x74) {
            unsigned int xmmreg = (instr[2] >> 3) & 7;
            uint8_t *xmmdst = (uint8_t *)asm_instr_ctx_xmm_addr(ctx, xmmreg);

            paramlen = decode_modrm_check(ctx, instr + 2, has_66_prefix, data_addr, NULL, NULL, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "pcmpeqb %s, xmm%u", operand_rm, xmmreg);
            free(operand_rm);
            for (i = 0; i < 16; i++) {
                xmmdst[i] = (xmmdst[i] == data[i]) ? 0xff : 0;
            }
            R_EIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 0f b6 /r: movzbl reg/mem8, reg */
        if (has_no_prefix && instr[1] == 0xb6) {
            paramlen = decode_modrm_check(ctx, instr + 2, has_66_prefix, data_addr, &op_reg, &operand_reg, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movzbl %s, %s", operand_rm, operand_reg);
            free(operand_rm);
            free(operand_reg);
            *op_reg = 0;
            memcpy(op_reg, data, 1);
            R_EIP(ctx) += 2 + paramlen;
            return true;
        }

        /* 0f b7 /r: movzwl reg/mem16, reg */
        if (has_no_prefix && instr[1] == 0xb7) {
            paramlen = decode_modrm_check(ctx, instr + 2, has_66_prefix, data_addr, &op_reg, &operand_reg, &operand_rm);
            if (!paramlen) {
                return false;
            }
            asm_printf(asm_instr, "movzwl %s, %s", operand_rm, operand_reg);
            free(operand_rm);
            free(operand_reg);
            *op_reg = 0;
            memcpy(op_reg, data, 2);
            R_EIP(ctx) += 2 + paramlen;
            return true;
        }
    }

    /* 38 /r: cmp reg8, reg/mem8 */
    if (instr[0] == 0x38) {
        paramlen = decode_modrm_check(ctx, instr + 1, has_66_prefix, data_addr, NULL, NULL, &operand_rm);
        if (!paramlen) {
            return false;
        }
        operand_reg = malloc(5);
        assert(operand_reg);
        op_reg = get_gp_reg(ctx, ((instr[1] >> 3) & 7), 8, operand_reg);
        asm_printf(asm_instr, "cmp %s, %s", operand_reg, operand_rm);
        free(operand_rm);
        free(operand_reg);
        R_EFL(ctx) = update_eflags_diff8(R_EFL(ctx), (uint8_t)(data[0] - *(uint8_t *)op_reg));
        R_EIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 8a /r: mov reg/mem8, reg8 */
    if (instr[0] == 0x8a) {
        paramlen = decode_modrm_check(ctx, instr + 1, 0, data_addr, NULL, NULL, &operand_rm);
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
        R_EIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 8b /r: mov reg/mem, reg */
    if (instr[0] == 0x8b) {
        paramlen = decode_modrm_check(ctx, instr + 1, has_66_prefix, data_addr, &op_reg, &operand_reg, &operand_rm);
        if (!paramlen) {
            return false;
        }
        asm_printf(asm_instr, "mov %s, %s", operand_rm, operand_reg);
        free(operand_rm);
        free(operand_reg);
        if (has_66_prefix) {
            *op_reg = 0;
            memcpy(op_reg, data, 2);
        } else {
            memcpy(op_reg, data, 4);
        }
        R_EIP(ctx) += 1 + paramlen;
        return true;
    }

    /* 80 /7 ib: cmpb imm8, reg/mem8 */
    if (instr[0] == 0x80 && (instr[1] & 0x38) == 0x38) {
        int8_t op1 = (int8_t)data[0], op2 = 0;

        paramlen = decode_modrm_check(ctx, instr + 1, has_66_prefix, data_addr, NULL, NULL, &operand_rm);
        if (!paramlen) {
            return false;
        }
        op2 = (int8_t)instr[1 + paramlen];
        asm_printf(asm_instr, "cmpb 0x%02x, %s", op2, operand_rm);
        free(operand_rm);
        R_EFL(ctx) = update_eflags_diff8(R_EFL(ctx), (uint8_t)(op1 - op2));
        R_EIP(ctx) += 2 + paramlen;
        return true;
    }

    /* a4: movsb %ds:(%esi), %es:(%edi) */
    if (has_no_prefix && instr[0] == 0xa4) {
        uintptr_t computed_addr = (uintptr_t)R_ESI(ctx);
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter esi is not address %" PRIxPTR "\n", data_addr);
            return 0;
        }
        asm_printf(asm_instr, "movsb (esi=0x%" PRIxREG "), (edi)", R_ESI(ctx));
        *(uint8_t *)R_EDI(ctx) = *data;
        R_ESI(ctx) += 1;
        R_EDI(ctx) += 1;
        R_EIP(ctx) += 1;
        return true;
    }

    /* f3 a4: rep movsb %ds:(%esi),%es:(%edi) */
    if (has_f3_prefix && instr[0] == 0xa4) {
        size_t len;
        uintptr_t computed_addr = (uintptr_t)R_ESI(ctx);
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter esi is not address %" PRIxPTR "\n", data_addr);
            return false;
        }
        asm_printf(asm_instr, "rep movsb (esi=0x%" PRIxREG "), (edi)", R_ESI(ctx));
        len = (size_t)R_ECX(ctx);
        memcpy((void *)R_EDI(ctx), data, len);
        R_ESI(ctx) += len;
        R_EDI(ctx) += len;
        R_ECX(ctx) = 0;
        R_EIP(ctx) += 1;
        return true;
    }

    /* 66 a5: movsw %ds:(%esi), %es:(%edi) */
    if (has_66_prefix && instr[0] == 0xa5) {
        uintptr_t computed_addr = (uintptr_t)R_ESI(ctx);
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter esi is not address %" PRIxPTR "\n", data_addr);
            return 0;
        }
        asm_printf(asm_instr, "movsw (esi=0x%" PRIxREG "), (edi)", R_ESI(ctx));
        memcpy((void *)R_EDI(ctx), data, 2);
        R_ESI(ctx) += 2;
        R_EDI(ctx) += 2;
        R_EIP(ctx) += 1;
        return true;
    }

    /* f3 a5: rep movsl %ds:(%esi), %es:(%edi) */
    if (has_f3_prefix && instr[0] == 0xa5) {
        size_t len;
        uintptr_t computed_addr = (uintptr_t)R_ESI(ctx);
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter esi is not address %" PRIxPTR "\n", data_addr);
            return 0;
        }
        asm_printf(asm_instr, "rep movsl (esi=0x%" PRIxREG "), (edi)", R_ESI(ctx));
        len = (size_t)R_ECX(ctx);
        assert(len < 0x40000000);
        memcpy((void *)R_EDI(ctx), data, len * 4);
        R_ESI(ctx) += len * 4;
        R_EDI(ctx) += len * 4;
        R_ECX(ctx) = 0;
        R_EIP(ctx) += 1;
        return true;
    }

    /* f2 ae: repnz scas %es:(%edi), %al */
    if (has_f2_prefix && instr[0] == 0xae) {
        uint8_t al = R_EAX(ctx) & 0xff;
        uintptr_t computed_addr = (uintptr_t)R_EDI(ctx);
        if (computed_addr != data_addr) {
            fprintf(stderr, "Error: mem parameter edi is not address %" PRIxPTR "\n", data_addr);
            return false;
        }
        for (i = 0; i < datalen && data[i] != al && R_ECX(ctx); i++) {
            R_ECX(ctx) -= 1;
        }
        assert(i < datalen);
        asm_printf(asm_instr, "repnz scas (edi=0x%" PRIxREG "), al=0x%02x", R_EDI(ctx), al);
        R_EDI(ctx) += i;
        R_EIP(ctx) += 1;
        R_ECX(ctx) -= 1;
        return true;
    }

    instr = orig_instr;
    fprintf(stderr, "Unknown x86 instruction @%p: %02x %02x %02x %02x %02x %02x\n",
            (const void *)instr, instr[0], instr[1], instr[2], instr[3], instr[4], instr[5]);
    return false;
}
