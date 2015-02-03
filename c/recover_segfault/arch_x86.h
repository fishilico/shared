#ifndef ARCH_X86
#define ARCH_X86

#include "recover_segfault.h"

/* printf format for general purpose registers */
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
/* Windows uses DWORD as unsigned long int */
#    define PRIxREG "lx"
#else
#    define PRIxREG PRIx32
#endif

/* Some processor flags, from Linux header asm/processor-flags.h */
#define X86_EFLAGS_CF 0x0001 /* Carry Flag */
#define X86_EFLAGS_PF 0x0004 /* Parity Flag */
#define X86_EFLAGS_AF 0x0010 /* Auxiliary carry Flag */
#define X86_EFLAGS_ZF 0x0040 /* Zero Flag */
#define X86_EFLAGS_SF 0x0080 /* Sign Flag */
#define X86_EFLAGS_OF 0x0800 /* Overflow Flag */

/* Get registers from a context */
#define R_EAX(ctx) asm_instr_ctx_reg((ctx), EAX, Eax)
#define R_EBX(ctx) asm_instr_ctx_reg((ctx), EBX, Ebx)
#define R_ECX(ctx) asm_instr_ctx_reg((ctx), ECX, Ecx)
#define R_EDX(ctx) asm_instr_ctx_reg((ctx), EDX, Edx)
#define R_ESP(ctx) asm_instr_ctx_reg((ctx), ESP, Esp)
#define R_EBP(ctx) asm_instr_ctx_reg((ctx), EBP, Ebp)
#define R_ESI(ctx) asm_instr_ctx_reg((ctx), ESI, Esi)
#define R_EDI(ctx) asm_instr_ctx_reg((ctx), EDI, Edi)
#define R_EIP(ctx) asm_instr_ctx_reg((ctx), EIP, Eip)
#define R_EFL(ctx) asm_instr_ctx_reg((ctx), EFL, EFlags)

typedef asm_instr_ctx_regtype(EAX, Eax) asm_instr_reg;

/* XMM registers for SSE2, low double-word part */
#define R_XMM0LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 0))
#define R_XMM1LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 1))
#define R_XMM2LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 2))
#define R_XMM3LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 3))
#define R_XMM4LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 4))
#define R_XMM5LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 5))
#define R_XMM6LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 6))
#define R_XMM7LL(ctx) (*(asm_instr_reg*)(void*)asm_instr_ctx_xmm_addr((ctx), 7))

#endif /* ARCH_X86 */
