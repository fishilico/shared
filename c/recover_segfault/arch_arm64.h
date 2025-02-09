#ifndef ARCH_ARM64
#define ARCH_ARM64

#include "recover_segfault.h"

/* printf format for general purpose registers */
#include <inttypes.h>
#define PRIxREG PRIx64

/* Flags in Saved Program Status Registers (SPSR) */
#define ARM64_PSR_Q 0x08000000 /* Overflow or saturaion Flag */
#define ARM64_PSR_V 0x10000000 /* Signed Overflow Flag */
#define ARM64_PSR_C 0x20000000 /* Carry Flag */
#define ARM64_PSR_Z 0x40000000 /* Zero Flag */
#define ARM64_PSR_N 0x80000000 /* Negative Flag */

/* Get registers from a context */
#define R_SP(ctx) asm_instr_ctx_reg_lw((ctx), sp, Sp)
#define R_PC(ctx) asm_instr_ctx_reg_lw((ctx), pc, Pc)
#define R_CPSR(ctx) asm_instr_ctx_reg_lw((ctx), pstate, Cpsr)
#define R_X(ctx, num) asm_instr_ctx_reg_lw((ctx), regs[num], X[num])
#define R_X0(ctx) R_X((ctx), 0)
#define R_X1(ctx) R_X((ctx), 1)
#define R_X2(ctx) R_X((ctx), 2)
#define R_X3(ctx) R_X((ctx), 3)
#define R_X4(ctx) R_X((ctx), 4)
#define R_X5(ctx) R_X((ctx), 5)
#define R_X6(ctx) R_X((ctx), 6)
#define R_X7(ctx) R_X((ctx), 7)
#define R_X8(ctx) R_X((ctx), 8)
#define R_X9(ctx) R_X((ctx), 9)
#define R_X10(ctx) R_X((ctx), 10)
#define R_X11(ctx) R_X((ctx), 11)
#define R_X12(ctx) R_X((ctx), 12)
#define R_X13(ctx) R_X((ctx), 13)
#define R_X14(ctx) R_X((ctx), 14)
#define R_X15(ctx) R_X((ctx), 15)
#define R_X16(ctx) R_X((ctx), 16)
#define R_X17(ctx) R_X((ctx), 17)
#define R_X18(ctx) R_X((ctx), 18)
#define R_X19(ctx) R_X((ctx), 19)
#define R_X20(ctx) R_X((ctx), 20)
#define R_X21(ctx) R_X((ctx), 21)
#define R_X22(ctx) R_X((ctx), 22)
#define R_X23(ctx) R_X((ctx), 23)
#define R_X24(ctx) R_X((ctx), 24)
#define R_X25(ctx) R_X((ctx), 25)
#define R_X26(ctx) R_X((ctx), 26)
#define R_X27(ctx) R_X((ctx), 27)
#define R_X28(ctx) R_X((ctx), 28)
#define R_X29(ctx) R_X((ctx), 29)
#define R_X30(ctx) R_X((ctx), 30)

typedef uint64_t asm_instr_reg;

/* Get unsigned value of registers from a context */
#define R_PC_U(ctx) ((uint64_t)R_PC(ctx))

#endif /* ARCH_ARM64 */
