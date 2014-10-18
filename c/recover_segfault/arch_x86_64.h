#ifndef ARCH_X86_64
#define ARCH_X86_64

#include "recover_segfault.h"

/* printf format for general purpose registers */
#if defined(__linux__) || defined(__unix__) || defined(__posix__)
#    define PRIxREG "llx"
#else
#    define PRIxREG PRIx64
#endif

/* Some processor flags, from Linux header asm/processor-flags.h */
#define X86_EFLAGS_CF 0x0001 /* Carry Flag */
#define X86_EFLAGS_PF 0x0004 /* Parity Flag */
#define X86_EFLAGS_AF 0x0010 /* Auxiliary carry Flag */
#define X86_EFLAGS_ZF 0x0040 /* Zero Flag */
#define X86_EFLAGS_SF 0x0080 /* Sign Flag */
#define X86_EFLAGS_OF 0x0800 /* Overflow Flag */

/* Instruction REX prefix bits */
#define X86_64_REX_B 1
#define X86_64_REX_X 2
#define X86_64_REX_R 4
#define X86_64_REX_W 8
/* Use high nibble to encode "reg8" in ModR/M decoder */
#define X86_64_REX_FAKE_R8 0x10

/* Get registers from a context */
#define R_RAX(ctx) asm_instr_ctx_reg((ctx), RAX, Rax)
#define R_RBX(ctx) asm_instr_ctx_reg((ctx), RBX, Rbx)
#define R_RCX(ctx) asm_instr_ctx_reg((ctx), RCX, Rcx)
#define R_RDX(ctx) asm_instr_ctx_reg((ctx), RDX, Rdx)
#define R_RSP(ctx) asm_instr_ctx_reg((ctx), RSP, Rsp)
#define R_RBP(ctx) asm_instr_ctx_reg((ctx), RBP, Rbp)
#define R_RSI(ctx) asm_instr_ctx_reg((ctx), RSI, Rsi)
#define R_RDI(ctx) asm_instr_ctx_reg((ctx), RDI, Rdi)
#define R_R8(ctx) asm_instr_ctx_reg((ctx), R8, R8)
#define R_R9(ctx) asm_instr_ctx_reg((ctx), R9, R9)
#define R_R10(ctx) asm_instr_ctx_reg((ctx), R10, R10)
#define R_R11(ctx) asm_instr_ctx_reg((ctx), R11, R11)
#define R_R12(ctx) asm_instr_ctx_reg((ctx), R12, R12)
#define R_R13(ctx) asm_instr_ctx_reg((ctx), R13, R13)
#define R_R14(ctx) asm_instr_ctx_reg((ctx), R14, R14)
#define R_R15(ctx) asm_instr_ctx_reg((ctx), R15, R15)
#define R_RIP(ctx) asm_instr_ctx_reg((ctx), RIP, Rip)
#define R_EFL(ctx) asm_instr_ctx_reg((ctx), EFL, EFlags)

typedef asm_instr_ctx_regtype(RAX, Rax) asm_instr_reg;

/* XMM registers for SSE2 */
#ifdef __clang__
/* Trick alignment check on clang by casting first to void* */
#    define asm_instr_ctx_xmm_low(ctx, num) (((asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), num))[0])
#    define asm_instr_ctx_xmm_high(ctx, num) (((asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), num))[1])
#else
/* Trick strict aliasing by casting first to uintptr_t */
#    define asm_instr_ctx_xmm_low(ctx, num) (((asm_instr_reg*)(uintptr_t)asm_instr_ctx_xmm_addr((ctx), num))[0])
#    define asm_instr_ctx_xmm_high(ctx, num) (((asm_instr_reg*)(uintptr_t)asm_instr_ctx_xmm_addr((ctx), num))[1])
#endif

#define R_XMM0L(ctx) asm_instr_ctx_xmm_low((ctx), 0)
#define R_XMM0H(ctx) asm_instr_ctx_xmm_high((ctx), 0)
#define R_XMM1L(ctx) asm_instr_ctx_xmm_low((ctx), 1)
#define R_XMM1H(ctx) asm_instr_ctx_xmm_high((ctx), 1)
#define R_XMM2L(ctx) asm_instr_ctx_xmm_low((ctx), 2)
#define R_XMM2H(ctx) asm_instr_ctx_xmm_high((ctx), 2)
#define R_XMM3L(ctx) asm_instr_ctx_xmm_low((ctx), 3)
#define R_XMM3H(ctx) asm_instr_ctx_xmm_high((ctx), 3)
#define R_XMM4L(ctx) asm_instr_ctx_xmm_low((ctx), 4)
#define R_XMM4H(ctx) asm_instr_ctx_xmm_high((ctx), 4)
#define R_XMM5L(ctx) asm_instr_ctx_xmm_low((ctx), 5)
#define R_XMM5H(ctx) asm_instr_ctx_xmm_high((ctx), 5)
#define R_XMM6L(ctx) asm_instr_ctx_xmm_low((ctx), 6)
#define R_XMM6H(ctx) asm_instr_ctx_xmm_high((ctx), 6)
#define R_XMM7L(ctx) asm_instr_ctx_xmm_low((ctx), 7)
#define R_XMM7H(ctx) asm_instr_ctx_xmm_high((ctx), 7)
#define R_XMM8L(ctx) asm_instr_ctx_xmm_low((ctx), 8)
#define R_XMM8H(ctx) asm_instr_ctx_xmm_high((ctx), 8)
#define R_XMM9L(ctx) asm_instr_ctx_xmm_low((ctx), 9)
#define R_XMM9H(ctx) asm_instr_ctx_xmm_high((ctx), 9)
#define R_XMM10L(ctx) asm_instr_ctx_xmm_low((ctx), 10)
#define R_XMM10H(ctx) asm_instr_ctx_xmm_high((ctx), 10)
#define R_XMM11L(ctx) asm_instr_ctx_xmm_low((ctx), 11)
#define R_XMM11H(ctx) asm_instr_ctx_xmm_high((ctx), 11)
#define R_XMM12L(ctx) asm_instr_ctx_xmm_low((ctx), 12)
#define R_XMM12H(ctx) asm_instr_ctx_xmm_high((ctx), 12)
#define R_XMM13L(ctx) asm_instr_ctx_xmm_low((ctx), 13)
#define R_XMM13H(ctx) asm_instr_ctx_xmm_high((ctx), 13)
#define R_XMM14L(ctx) asm_instr_ctx_xmm_low((ctx), 14)
#define R_XMM14H(ctx) asm_instr_ctx_xmm_high((ctx), 14)
#define R_XMM15L(ctx) asm_instr_ctx_xmm_low((ctx), 15)
#define R_XMM15H(ctx) asm_instr_ctx_xmm_high((ctx), 15)

#endif /* ARCH_X86_64 */
