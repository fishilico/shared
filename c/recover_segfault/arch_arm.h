#ifndef ARCH_ARM
#define ARCH_ARM

#include "recover_segfault.h"

/* printf format for general purpose registers */
#include <inttypes.h>
#define PRIxREG PRIx32

/* Some CPSR flags */
#define ARM_CPSR_T 0x00000020 /* Thumb state */
#define ARM_CPSR_F 0x00000040 /* Enable FIQ */
#define ARM_CPSR_I 0x00000080 /* Enable IRQ */
#define ARM_CPSR_V 0x10000000 /* Overflow */
#define ARM_CPSR_C 0x20000000 /* Carry */
#define ARM_CPSR_Z 0x40000000 /* Zero */
#define ARM_CPSR_N 0x80000000 /* Negative */

/* Get registers from a context
 * * r11 is fp (frame pointer)
 * * r12 is ip (intra-procedure call scratch register)
 * * r13 is sp (stack pointer)
 * * r14 is lr (link register)
 * * r15 is pc (program counter)
 * * flags are is cpsr (current program state register)
 */
#define R_R0(ctx) asm_instr_ctx_reg_lw((ctx), arm_r0, R0)
#define R_R1(ctx) asm_instr_ctx_reg_lw((ctx), arm_r1, R1)
#define R_R2(ctx) asm_instr_ctx_reg_lw((ctx), arm_r2, R2)
#define R_R3(ctx) asm_instr_ctx_reg_lw((ctx), arm_r3, R3)
#define R_R4(ctx) asm_instr_ctx_reg_lw((ctx), arm_r4, R4)
#define R_R5(ctx) asm_instr_ctx_reg_lw((ctx), arm_r5, R5)
#define R_R6(ctx) asm_instr_ctx_reg_lw((ctx), arm_r6, R6)
#define R_R7(ctx) asm_instr_ctx_reg_lw((ctx), arm_r7, R7)
#define R_R8(ctx) asm_instr_ctx_reg_lw((ctx), arm_r8, R8)
#define R_R9(ctx) asm_instr_ctx_reg_lw((ctx), arm_r9, R9)
#define R_R10(ctx) asm_instr_ctx_reg_lw((ctx), arm_r10, R10)
#define R_FP(ctx) asm_instr_ctx_reg_lw((ctx), arm_fp, R11)
#define R_IP(ctx) asm_instr_ctx_reg_lw((ctx), arm_ip, R12)
#define R_SP(ctx) asm_instr_ctx_reg_lw((ctx), arm_sp, R13)
#define R_LR(ctx) asm_instr_ctx_reg_lw((ctx), arm_lr, R14)
#define R_PC(ctx) asm_instr_ctx_reg_lw((ctx), arm_pc, R15)
#define R_CPSR(ctx) asm_instr_ctx_reg_lw((ctx), arm_cpsr, R15)

typedef asm_instr_ctx_regtype(arm_r0, R0) asm_instr_reg;

/* Get unsigned value of registers from a context */
#define R_PC_U(ctx) ((uint32_t)R_PC(ctx))

#endif /* ARCH_ARM */
