/**
 * Common helper across architectures
 */
#include "recover_segfault.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * Write an ASM instruction text into a buffer, with format
 */
void asm_printf(char *asm_instr, const char *format, ...)
{
    va_list ap;

    if (!asm_instr) {
        return;
    }

    va_start(ap, format);
    vsnprintf(asm_instr, ASM_INSTR_BUFSIZE, format, ap);
    va_end(ap);
    asm_instr[ASM_INSTR_BUFSIZE - 1] = '\0';
}

/**
 * Run an ASM instruction which moves data, and eventually print what's done
 */
bool run_mov_asm_instruction(asm_instr_context *ctx, uintptr_t data_addr, uint8_t *data, size_t datalen)
{
#ifdef DEBUG
    char asm_instr[ASM_INSTR_BUFSIZE];

    if (run_mov_asm_instruction_p(ctx, data_addr, data, datalen, asm_instr)) {
        fprintf(stderr, "asm(%s)\n", asm_instr);
        return true;
    }
    return false;
#else
    return run_mov_asm_instruction_p(ctx, data_addr, data, datalen, NULL);
#endif
}
