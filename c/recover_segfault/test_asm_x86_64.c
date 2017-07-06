/**
 * Test the x86-64 implementation
 */
#include "arch_x86_64.h"

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
        _check_asm_instr_ctx_xmm_addr((asm_instr_context*)NULL, num)
check_asm_instr_ctx_xmm_addr(0);
check_asm_instr_ctx_xmm_addr(1);
check_asm_instr_ctx_xmm_addr(2);
check_asm_instr_ctx_xmm_addr(3);
check_asm_instr_ctx_xmm_addr(4);
check_asm_instr_ctx_xmm_addr(5);
check_asm_instr_ctx_xmm_addr(6);
check_asm_instr_ctx_xmm_addr(7);
check_asm_instr_ctx_xmm_addr(8);
check_asm_instr_ctx_xmm_addr(9);
check_asm_instr_ctx_xmm_addr(10);
check_asm_instr_ctx_xmm_addr(11);
check_asm_instr_ctx_xmm_addr(12);
check_asm_instr_ctx_xmm_addr(13);
check_asm_instr_ctx_xmm_addr(14);
check_asm_instr_ctx_xmm_addr(15);
#endif

int main(void)
{
    asm_instr_context ctx;
    const uintptr_t data_addr = 0xda7a0000;
    uint8_t data[] = "\x17\x15\x7e\x57\xda\x7a\xb1\x0b It is test data blob";
    uint8_t olddata;
    int retval = 0;
    asm_instr_reg data64h;
    const asm_instr_reg data64 = 0x0bb17ada577e1517UL;
    const asm_instr_reg data32 = data64 & 0xffffffff;
    const asm_instr_reg data16 = data64 & 0xffff;
    const asm_instr_reg data8 = data64 & 0xff;

#ifdef CONTEXT_FPREGS_TYPE
    CONTEXT_FPREGS_TYPE ctx_fpregs;
#    define reset_ctx_fpregs() \
        do { \
            memset(&ctx_fpregs, 0, sizeof(ctx_fpregs)); \
            ctx.fpregs = &ctx_fpregs; \
        } while (0);
#else
#    define reset_ctx_fpregs() (void)0
#endif

    memcpy(&data64h, &data[8], sizeof(asm_instr_reg));
    memset(&ctx, 0, sizeof(ctx));
    reset_ctx_fpregs();

#define test(opcode, instrstr, reg, val) \
    do { \
        char asm_instr[ASM_INSTR_BUFSIZE] = ""; \
        const uint8_t instructions[] = opcode; \
        asm_instr_reg final_rip = (asm_instr_reg)&(instructions[sizeof(instructions) - 1]); \
        R_RIP(&ctx) = (asm_instr_reg)&instructions; \
        if (!run_mov_asm_instruction_p(&ctx, data_addr, data, sizeof(data), asm_instr)) { \
            printf("[FAIL] %-24s %s\n", #opcode, instrstr); \
            retval = 1; \
        } else if (strcmp(asm_instr, instrstr)) { \
            printf("[FAIL] %-24s\n...  decoded '%s'\n... expected '%s'\n", \
                   #opcode, asm_instr, instrstr); \
            retval = 1; \
        } else if (R_##reg(&ctx) != (val)) { \
            printf("[FAIL] %-24s %s: %s = 0x%"PRIxREG", expected 0x%"PRIxREG"\n", \
                   #opcode, instrstr, #reg, (asm_instr_reg)R_##reg(&ctx), (asm_instr_reg)(val)); \
            retval = 1; \
        } else if (R_RIP(&ctx) != final_rip) { \
            printf("[FAIL] %-24s %s: RIP is 0x%"PRIxREG" instead of 0x%"PRIxREG"\n", \
                   #opcode, instrstr, R_RIP(&ctx), final_rip); \
            retval = 1; \
        } else { \
            printf("[ OK ] %-24s %-36s ; %-3s = 0x%"PRIxREG"\n", \
                   #opcode, instrstr, #reg, (asm_instr_reg)R_##reg(&ctx)); \
        } \
        memset(&ctx, 0, sizeof(ctx)); \
        reset_ctx_fpregs(); \
    } while (0)

    /* Zero-extending load (movzx) */
    R_RSI(&ctx) = data_addr;
    test("\x0f\xb6\x06", "movzbl (rsi=0xda7a0000), eax", RAX, data8);
    R_RSI(&ctx) = data_addr;
    test("\x0f\xb6\x0e", "movzbl (rsi=0xda7a0000), ecx", RCX, data8);
    R_RBX(&ctx) = data_addr - 0x2a;
    test("\x0f\xb6\x53\x2a", "movzbl 0x2a(rbx=0xda79ffd6), edx", RDX, data8);
    R_RSI(&ctx) = data_addr;
    test("\x0f\xb7\x0e", "movzwl (rsi=0xda7a0000), ecx", RCX, data16);

    /* XOR */
    R_RAX(&ctx) = 0x123456;
    R_RDI(&ctx) = data_addr;
    test("\x48\x33\x07", "xor (rdi=0xda7a0000), rax", RAX, data64 ^ 0x123456);

    /* Load 64-bit value */
    R_RSI(&ctx) = data_addr;
    test("\x48\x8b\x06", "mov (rsi=0xda7a0000), rax", RAX, data64);
    R_RSI(&ctx) = data_addr - 0x08;
    test("\x4c\x8b\x46\x08", "mov 0x8(rsi=0xda79fff8), r8", R8, data64);
    R_RSI(&ctx) = data_addr - 0x10;
    test("\x4c\x8b\x4e\x10", "mov 0x10(rsi=0xda79fff0), r9", R9, data64);
    R_RSI(&ctx) = data_addr - 0x18;
    test("\x4c\x8b\x56\x18", "mov 0x18(rsi=0xda79ffe8), r10", R10, data64);

    /* Compare */
    R_RAX(&ctx) = data_addr;
    test("\x80\x38\x0a", "cmpb 0x0a, (rax=0xda7a0000)", EFL, X86_EFLAGS_PF);
    R_RAX(&ctx) = data_addr;
    test("\x80\x38\x17", "cmpb 0x17, (rax=0xda7a0000)", EFL, X86_EFLAGS_ZF);
    R_RCX(&ctx) = data_addr + 1;
    test("\x80\x79\xff\x0a", "cmpb 0x0a, -0x1(rcx=0xda7a0001)", EFL, X86_EFLAGS_PF);
    R_RAX(&ctx) = (asm_instr_reg)data_addr;
    R_RDX(&ctx) = data8 << 8;
    test("\x38\x30", "cmp dh, (rax=0xda7a0000)", EFL, X86_EFLAGS_ZF);
    R_RCX(&ctx) = data_addr;
    test("\x44\x38\x09", "cmp r9b, (rcx=0xda7a0000)", EFL, 0);
    R_RCX(&ctx) = data_addr;
    test("\x44\x3a\x11", "cmp (rcx=0xda7a0000), r10b", EFL, X86_EFLAGS_SF | X86_EFLAGS_PF);
    /* Special case for musl "for (i=l; i && s[i-1] != '\n'; i--);" */
    R_R13(&ctx) = data_addr;
    R_RBP(&ctx) = 1;
    test("\x41\x80\x7c\x2d\xff\x0a", "cmpb 0x0a, -0x1(r13+1*rbp=0xda7a0001)", EFL, X86_EFLAGS_PF);
    R_R13(&ctx) = data_addr;
    R_RBP(&ctx) = 2;
    test("\x41\x80\x7c\x2d\xfe\x17", "cmpb 0x17, -0x2(r13+1*rbp=0xda7a0002)", EFL, X86_EFLAGS_ZF);

    /* Load 32-bit value */
    R_RSI(&ctx) = data_addr;
    test("\x8b\x0e", "mov (rsi=0xda7a0000), ecx", RCX, data32);

    /* Load 8-bit value */
    R_RAX(&ctx) = 0;
    R_RBX(&ctx) = (asm_instr_reg)data_addr;
    test("\x8a\x03", "mov (rbx=0xda7a0000), al", RAX, data8);

    /* repnz scasb, used by strlen */
    R_RDI(&ctx) = data_addr;
    R_RCX(&ctx) = -1;
    test("\xf2\xae", "repnz scas (rdi=0xda7a0000), al=0x00",
        RDI, (asm_instr_reg)(data_addr + sizeof(data) - 1));
    R_RDI(&ctx) = data_addr;
    R_RCX(&ctx) = -1;
    test("\xf2\xae", "repnz scas (rdi=0xda7a0000), al=0x00",
        RCX, (asm_instr_reg)(-(sizeof(data) + 1)));

    /* SSE2 */
    R_RSI(&ctx) = data_addr;
    test("\x0f\x10\x06", "movups (rsi=0xda7a0000), xmm0", XMM0L, data64);
    R_RSI(&ctx) = data_addr;
    test("\x0f\x10\x06", "movups (rsi=0xda7a0000), xmm0", XMM0H, data64h);
    R_RAX(&ctx) = data_addr;
    test("\xf3\x44\x0f\x6f\x20", "movdqu (rax=0xda7a0000), xmm12", XMM12L, data64);
    R_RAX(&ctx) = data_addr;
    test("\xf3\x44\x0f\x6f\x20", "movdqu (rax=0xda7a0000), xmm12", XMM12H, data64h);
    R_RSI(&ctx) = data_addr;
    R_RDX(&ctx) = 0x10;
    test("\xf3\x44\x0f\x6f\x44\x16\xf0", "movdqu -0x10(rsi+1*rdx=0xda7a0010), xmm8", XMM8L, data64);
    R_RSI(&ctx) = data_addr;
    R_RDX(&ctx) = 0x10;
    test("\xf3\x44\x0f\x6f\x44\x16\xf0", "movdqu -0x10(rsi+1*rdx=0xda7a0010), xmm8", XMM8H, data64h);
    R_RSI(&ctx) = data_addr + 0x10;
    R_RDX(&ctx) = 0x10;
    test("\xc5\xfa\x6f\x74\x16\xe0", "vmovdqu -0x20(rsi+1*rdx=0xda7a0020), xmm6", XMM6L, data64);
    R_RSI(&ctx) = data_addr + 0x10;
    R_RDX(&ctx) = 0x10;
    test("\xc5\xfa\x6f\x74\x16\xe0", "vmovdqu -0x20(rsi+1*rdx=0xda7a0020), xmm6", XMM6H, data64h);
    R_RAX(&ctx) = data_addr - 0x20;
    test("\x66\x44\x0f\x74\x50\x20", "pcmpeqb 0x20(rax=0xda79ffe0), xmm10", XMM10L, 0);
    R_RAX(&ctx) = data_addr - 0x20;
    R_XMM10L(&ctx) = data64 & 0xff00ff;
    test("\x66\x44\x0f\x74\x50\x20", "pcmpeqb 0x20(rax=0xda79ffe0), xmm10", XMM10L, 0xff00ff);

    /* SSE 4.2 */
    R_RDI(&ctx) = data_addr - 0x10;
    test("\x66\x0f\x3a\x63\x4f\x10\x08", "pcmpistri 0x8, 0x10(rdi=0xda79fff0), xmm1", XMM1L, 0);
    R_RDI(&ctx) = data_addr - 0x10;
    test("\x66\x0f\x3a\x63\x4f\x10\x08", "pcmpistri 0x8, 0x10(rdi=0xda79fff0), xmm1", XMM1H, 0);
    R_RDI(&ctx) = data_addr - 0x10;
    test("\x66\x0f\x3a\x63\x4f\x10\x08", "pcmpistri 0x8, 0x10(rdi=0xda79fff0), xmm1", EFL,
        X86_EFLAGS_OF | X86_EFLAGS_SF);
    R_RDI(&ctx) = data_addr - 0x10;
    test("\x66\x0f\x3a\x63\x4f\x10\x08", "pcmpistri 0x8, 0x10(rdi=0xda79fff0), xmm1", RCX, 0x10);

    olddata = data[9];
    data[9] = 0;
    R_RDI(&ctx) = data_addr - 0x20;
    test("\x66\x0f\x3a\x63\x4f\x20\x08", "pcmpistri 0x8, 0x20(rdi=0xda79ffe0), xmm1", EFL,
        X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_SF | X86_EFLAGS_ZF);
    R_RDI(&ctx) = data_addr - 0x20;
    test("\x66\x0f\x3a\x63\x4f\x20\x08", "pcmpistri 0x8, 0x20(rdi=0xda79ffe0), xmm1", RCX, 9);
    data[9] = olddata;

    return retval;
}
