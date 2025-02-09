/**
 * Test the x86 implementation
 */
#include "arch_x86_32.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Compile-time check that asm_instr_ctx_xmm_addr_const, if defined, is asm_instr_ctx_xmm_addr
 * If the macro is not defined, define it as asm_instr_ctx_xmm_addr_const to compile the code.
 */
#ifdef asm_instr_ctx_xmm_addr_const

#    ifndef _STATIC_ASSERT
#        define _STATIC_ASSERT(cond) extern void __static_assert_t(int [(cond)?1:-1])
#    endif
#    define _check_asm_instr_ctx_xmm_addr(ctx, num) \
        _STATIC_ASSERT(asm_instr_ctx_xmm_addr_const(ctx, num) == asm_instr_ctx_xmm_addr(ctx, num))
#    define check_asm_instr_ctx_xmm_addr(num) \
        _check_asm_instr_ctx_xmm_addr((asm_instr_context *)NULL, num)
check_asm_instr_ctx_xmm_addr(0);
check_asm_instr_ctx_xmm_addr(1);
check_asm_instr_ctx_xmm_addr(2);
check_asm_instr_ctx_xmm_addr(3);
check_asm_instr_ctx_xmm_addr(4);
check_asm_instr_ctx_xmm_addr(5);
check_asm_instr_ctx_xmm_addr(6);
check_asm_instr_ctx_xmm_addr(7);
#endif

int main(void)
{
    asm_instr_context ctx;
    const uintptr_t data_addr = 0xda7a0000;
    uint8_t data[] = "\x17\x15\xda\x7a It is data";
    int retval = 0;
    const asm_instr_reg data32 = 0x7ada1517UL;
    const asm_instr_reg data16 = data32 & 0xffff;
    const asm_instr_reg data8 = data32 & 0xff;
    uint8_t buffer[100];

#ifdef CONTEXT_FPREGS_TYPE
    CONTEXT_FPREGS_TYPE ctx_fpregs;
#    define reset_ctx_fpregs() \
        do { \
            memset(&ctx_fpregs, 0, sizeof(ctx_fpregs)); \
            ctx.fpregs = (CONTEXT_FPREGS_PTYPE)&ctx_fpregs; \
        } while (0)
#else
#    define reset_ctx_fpregs() (void)0
#endif

    memset(&ctx, 0, sizeof(ctx));
    reset_ctx_fpregs();

#define test(opcode, instrstr, reg, val) \
    do { \
        char asm_instr[ASM_INSTR_BUFSIZE] = ""; \
        const uint8_t instructions[] = opcode; \
        asm_instr_reg final_eip = (asm_instr_reg)&(instructions[sizeof(instructions) - 1]); \
        R_EIP(&ctx) = (asm_instr_reg)&instructions; \
        if (!run_mov_asm_instruction_p(&ctx, data_addr, data, sizeof(data), asm_instr)) { \
            printf("[FAIL] %-24s %s\n", #opcode, instrstr); \
            retval = 1; \
        } else if (strcmp(asm_instr, instrstr)) { \
            printf("[FAIL] %-24s\n...  decoded '%s'\n... expected '%s'\n", \
                   #opcode, asm_instr, instrstr); \
            retval = 1; \
        } else if (R_##reg(&ctx) != (val)) { \
            printf("[FAIL] %-24s %s: %s = 0x%" PRIxREG ", expected 0x%" PRIxREG "\n", \
                   #opcode, instrstr, #reg, (uint32_t)R_##reg(&ctx), (uint32_t)(val)); \
            retval = 1; \
        } else if (R_EIP(&ctx) != final_eip) { \
            printf("[FAIL] %-24s %s: EIP is 0x%" PRIxREG " instead of 0x%" PRIxREG "\n", \
                   #opcode, instrstr, R_EIP_U(&ctx), (uint32_t)final_eip); \
            retval = 1; \
        } else { \
            printf("[ OK ] %-24s %-36s ; %-3s = 0x%" PRIxREG "\n", \
                   #opcode, instrstr, #reg, (uint32_t)R_##reg(&ctx)); \
        } \
        memset(&ctx, 0, sizeof(ctx)); \
        reset_ctx_fpregs(); \
    } while (0)

    /* Zero-extending load (movzx) */
    R_EAX(&ctx) = (asm_instr_reg)(data_addr - 42);
    test("\x0f\xb6\x50\x2a", "movzbl 0x2a(eax=0xda79ffd6), edx", EDX, data8);
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    test("\x0f\xb7\x0e", "movzwl (esi=0xda7a0000), ecx", ECX, data16);

    /* Load 32-bit value */
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    test("\x8b\x0e", "mov (esi=0xda7a0000), ecx", ECX, data32);
    R_ESI(&ctx) = (asm_instr_reg)(data_addr - 0x08);
    test("\x8b\x56\x08", "mov 0x8(esi=0xda79fff8), edx", EDX, data32);

    /* Load 8-bit value */
    R_EAX(&ctx) = 0;
    R_EBX(&ctx) = (asm_instr_reg)data_addr;
    test("\x8a\x03", "mov (ebx=0xda7a0000), al", EAX, data8);

    /* Compare */
    R_EAX(&ctx) = (asm_instr_reg)data_addr;
    test("\x80\x38\x0a", "cmpb 0x0a, (eax=0xda7a0000)", EFL, X86_EFLAGS_PF);
    R_EAX(&ctx) = (asm_instr_reg)data_addr;
    test("\x80\x38\x17", "cmpb 0x17, (eax=0xda7a0000)", EFL, X86_EFLAGS_ZF);
    R_ECX(&ctx) = (asm_instr_reg)(data_addr + 1);
    test("\x80\x79\xff\x0a", "cmpb 0x0a, -0x1(ecx=0xda7a0001)", EFL, X86_EFLAGS_PF);
    R_EAX(&ctx) = (asm_instr_reg)data_addr;
    R_EDX(&ctx) = data8 << 8;
    test("\x38\x30", "cmp dh, (eax=0xda7a0000)", EFL, X86_EFLAGS_ZF);

    /* repnz scasb, used by strlen */
    R_EDI(&ctx) = (asm_instr_reg)data_addr;
    R_ECX(&ctx) = -1;
    test("\xf2\xae", "repnz scas (edi=0xda7a0000), al=0x00",
        EDI, (asm_instr_reg)(data_addr + sizeof(data) - 1));
    R_EDI(&ctx) = (asm_instr_reg)data_addr;
    R_ECX(&ctx) = -1;
    test("\xf2\xae", "repnz scas (edi=0xda7a0000), al=0x00",
        ECX, (asm_instr_reg)(-(sizeof(data) + 1)));

    /* Move data from string to string */
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    test("\xa4", "movsb (esi=0xda7a0000), (edi)", ESI, (asm_instr_reg)(data_addr + 1));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    test("\xa4", "movsb (esi=0xda7a0000), (edi)", EDI, (asm_instr_reg)(&buffer[1]));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    test("\x66\xa5", "movsw (esi=0xda7a0000), (edi)", ESI, (asm_instr_reg)(data_addr + 2));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    test("\x66\xa5", "movsw (esi=0xda7a0000), (edi)", EDI, (asm_instr_reg)(&buffer[2]));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    test("\xa5", "movsl (esi=0xda7a0000), (edi)", ESI, (asm_instr_reg)(data_addr + 4));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    test("\xa5", "movsl (esi=0xda7a0000), (edi)", EDI, (asm_instr_reg)(&buffer[4]));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    R_ECX(&ctx) = 2;
    test("\xf3\xa5", "rep movsl (esi=0xda7a0000), (edi)", ESI, (asm_instr_reg)(data_addr + 8));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    R_ECX(&ctx) = 2;
    test("\xf3\xa5", "rep movsl (esi=0xda7a0000), (edi)", EDI, (asm_instr_reg)(&buffer[8]));
    R_ESI(&ctx) = (asm_instr_reg)data_addr;
    R_EDI(&ctx) = (asm_instr_reg)buffer;
    R_ECX(&ctx) = 2;
    test("\xf3\xa5", "rep movsl (esi=0xda7a0000), (edi)", ECX, 0);

    /* SSE2 */
    R_EDI(&ctx) = (asm_instr_reg)data_addr;
    test("\xf3\x0f\x6f\x0f", "movdqu (edi=0xda7a0000), xmm1", XMM1LL, data32);
    R_EAX(&ctx) = (asm_instr_reg)(data_addr - 0x23);
    test("\xf3\x0f\x7e\x40\x23", "movq 0x23(eax=0xda79ffdd), xmm0", XMM0LL, data32);
    R_EAX(&ctx) = (asm_instr_reg)(data_addr - 0x10);
    test("\x66\x0f\x74\x40\x10", "pcmpeqb 0x10(eax=0xda79fff0), xmm0", XMM0LL, 0);
    R_EAX(&ctx) = (asm_instr_reg)(data_addr - 0x20);
    R_XMM4LL(&ctx) = data32 & 0xff00ff;
    test("\x66\x0f\x74\x60\x20", "pcmpeqb 0x20(eax=0xda79ffe0), xmm4", XMM4LL, 0xff00ff);
    return retval;
}
