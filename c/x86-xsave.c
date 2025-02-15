/**
 * Dump XSAVE state on an x86 CPU
 *
 * Inspiration from Linux MPX selftest program:
 * https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/x86/mpx-mini-test.c
 *
 * Documentation:
 * * http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/fpu/xstate.c
 * * http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/fpu/types.h
 * * http://events.linuxfoundation.org/sites/events/files/slides/LinuxCon_NA_2014.pdf
 *
 * Output example (on a Skylake processor)
 *     CPUID 0xd.0:
 *       (edx:eax) XSAVE processor supported state mask: 0x1f
 *       (ecx) required size of XSAVE for all supported components: 1088 = 0x440 bytes
 *       (ebx) required size of XSAVE for all enabled components: 1088 = 0x440 bytes
 *     (XCR0) XSAVE OS supported state mask: 0x1f
 *       [ 0] +FP (x87 Floating Point Unit)
 *             0000..009f (160 bytes at offset 0)
 *       [ 1] +SSE (Streaming SIMD Extension)
 *             00a0..01ff (352 bytes at offset 160)
 *       [ 2] +AVX YMM (Advanced Vector Extension)
 *             0240..033f (256 bytes at offset 576)
 *       [ 3] +MPX BNDREGS (Memory Protection Extension Bound Registers)
 *             03c0..03ff (64 bytes at offset 960)
 *       [ 4] +MPX BNDCSR (Memory Protection Extension CSR)
 *             0400..043f (64 bytes at offset 1024)
 *       [ 5] -AVX-512 opmask (k0-k7 registers)
 *       [ 6] -AVX-512 ZMM_Hi256 (upper 256 bits of ZMM0-ZMM15)
 *       [ 7] -AVX-512 Hi_ZMM256 (ZMM16-ZMM31)
 *       [ 8] -PT (Intel Processor Trace MSRs)
 *       [ 9] -PKRU (Protection Keys Rights for User Pages)
 *
 *     Current processor extended states:
 *       000000:  7f 03 00 00  00 00 00 00  00 00 00 00  00 00 00 00  FCW, FSW, FTW, FOP, FPU IP, CS
 *       000010:  00 00 00 00  00 00 00 00  80 1f 00 00  ff ff 00 00  FPU DP, DS, (reserved), MXCSR, MXCSR_MASK
 *       000020:                       (zeros)                        ST0 MM0 (10 bytes)
 *       000030:                       (zeros)                        ST1 MM1 (10 bytes)
 *       000040:                       (zeros)                        ST2 MM2 (10 bytes)
 *       000050:                       (zeros)                        ST3 MM3 (10 bytes)
 *       000060:                       (zeros)                        ST4 MM4 (10 bytes)
 *       000070:                       (zeros)                        ST5 MM5 (10 bytes)
 *       000080:                       (zeros)                        ST6 MM6 (10 bytes)
 *       000090:                       (zeros)                        ST7 MM7 (10 bytes)
 *       0000a0:  00 ff 00 00  00 00 00 00  00 00 00 00  00 00 00 00  XMM0 (16 bytes)
 *       0000b0:  25 25 25 25  25 25 25 25  25 25 25 25  25 25 25 25  XMM1 (16 bytes)
 *       0000c0:  20 66 6f 72  20 55 73 65  72 20 50 61  67 65 73 29  XMM2 (16 bytes)
 *       0000d0:                       (zeros)                        XMM3 (16 bytes)
 *       0000e0:  00 ff 00 00  00 00 00 00  00 00 00 00  00 00 00 00  XMM4 (16 bytes)
 *       0000f0:                       (zeros)                        XMM5 (16 bytes)
 *       000100:                       (zeros)                        XMM6 (16 bytes)
 *       000110:                       (zeros)                        XMM7 (16 bytes)
 *       000120:                       (zeros)                        XMM8 (16 bytes)
 *       000130:                       (zeros)                        XMM9 (16 bytes)
 *       000140:                       (zeros)                        XMM10 (16 bytes)
 *       000150:                       (zeros)                        XMM11 (16 bytes)
 *       000160:                       (zeros)                        XMM12 (16 bytes)
 *       000170:                       (zeros)                        XMM13 (16 bytes)
 *       000180:                       (zeros)                        XMM14 (16 bytes)
 *       000190:                       (zeros)                        XMM15 (16 bytes)
 *       0001a0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (FXSAVE reserved)
 *       0001b0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (FXSAVE reserved)
 *       0001c0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (FXSAVE reserved)
 *       0001d0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (FXSAVE reserved)
 *       0001e0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (FXSAVE reserved)
 *       0001f0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (FXSAVE reserved)
 *       000200:  [02/e2] .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  XSTATE_BV, (XSTATE header reserved)
 *       000210:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (XSTATE header reserved)
 *       000220:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (XSTATE header reserved)
 *       000230:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (XSTATE header reserved)
 *       000240:                       (zeros)                        YMM0[255:128]
 *       000250:                       (zeros)                        YMM1[255:128]
 *       000260:                       (zeros)                        YMM2[255:128]
 *       000270:                       (zeros)                        YMM3[255:128]
 *       000280:                       (zeros)                        YMM4[255:128]
 *       000290:                       (zeros)                        YMM5[255:128]
 *       0002a0:                       (zeros)                        YMM6[255:128]
 *       0002b0:                       (zeros)                        YMM7[255:128]
 *       0002c0:                       (zeros)                        YMM8[255:128]
 *       0002d0:                       (zeros)                        YMM9[255:128]
 *       0002e0:                       (zeros)                        YMM10[255:128]
 *       0002f0:                       (zeros)                        YMM11[255:128]
 *       000300:                       (zeros)                        YMM12[255:128]
 *       000310:                       (zeros)                        YMM13[255:128]
 *       000320:                       (zeros)                        YMM14[255:128]
 *       000330:                       (zeros)                        YMM15[255:128]
 *       000340:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       000350:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       000360:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       000370:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       000380:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       000390:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       0003a0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       0003b0:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..
 *       0003c0:                       (zeros)                        MPX BNDREG0_lower, BNDREG0_upper
 *       0003d0:                       (zeros)                        MPX BNDREG1_lower, BNDREG1_upper
 *       0003e0:                       (zeros)                        MPX BNDREG2_lower, BNDREG2_upper
 *       0003f0:                       (zeros)                        MPX BNDREG3_lower, BNDREG3_upper
 *       000400:                       (zeros)                        MPX BNDCFGU, BNDSTATUS
 *       000410:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (MPX BNDCSR padding)
 *       000420:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (MPX BNDCSR padding)
 *       000430:  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ..  (MPX BNDCSR padding)
 */
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct xstate_metadata {
    /* Description of the bit in XCR0 */
    const char *desc;
    /* Offset and size of the feature */
    uint32_t offset, size;
};
__extension__ static struct xstate_metadata xstate_desc[65] = {
    [0] = {"FP (x87 Floating Point Unit)", 0, 160},
    [1] = {"SSE (Streaming SIMD Extension)", 0xa0, 352},
    /* Use special out-of-bound value to define XSAVE header */
    [64] = {"XSTATE header", 0x200, 64},
    /* The following extensions may have dynamic offsets */
    [2] = {"AVX YMM (Advanced Vector Extension)", 0, 256},
    [3] = {"MPX BNDREGS (Memory Protection Extension Bound Registers)", 0, 64},
    [4] = {"MPX BNDCSR (Memory Protection Extension CSR)", 0, 64},
    [5] = {"AVX-512 opmask (k0-k7 registers)", 0, 64},
    [6] = {"AVX-512 ZMM_Hi256 (upper 256 bits of ZMM0-ZMM15)", 0, 512},
    [7] = {"AVX-512 Hi_ZMM256 (ZMM16-ZMM31)", 0, 1024},
    [8] = {"PT (Intel Processor Trace MSRs)", 0, 0},
    [9] = {"PKRU (Protection Keys Rights for User Pages)", 0, 8},
};

static void asm_cpuid(uint32_t code, uint32_t *peax, uint32_t *pebx, uint32_t *pecx, uint32_t *pedx)
{
#if defined(__i386__) && defined(__GNUC__) && defined(__PIC__)
    /* x86 GCC with PIC flag (Program Independent Code) complains with
     * "error: inconsistent operand constraints in an 'asm'"
     * because ebx has a special meaning in PIC
     */
    __asm__ volatile ("xchgl %%ebx, %1 ; cpuid ; xchgl %%ebx, %1"
        : "=a"(*peax), "=r"(*pebx), "=c"(*pecx), "=d"(*pedx)
        :"0"(code), "1"(*pebx), "2"(*pecx), "3"(*pedx));
#else
    __asm__ volatile ("cpuid"
        :"=a"(*peax), "=b"(*pebx), "=c"(*pecx), "=d"(*pedx)
        :"0"(code), "1"(*pebx), "2"(*pecx), "3"(*pedx));
#endif
}

static uint64_t xgetbv(uint32_t index)
{
    uint32_t eax, edx;

    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" /* xgetbv */
        : "=a" (eax), "=d" (edx)
        : "c" (index));
    return eax + ((uint64_t)edx << 32);
}

static void xsave(void *dest, uint64_t mask)
{
    uint32_t eax = (uint32_t)mask;
    uint32_t edx = (uint32_t)(mask >> 32);

#if defined(__x86_64__)
    __asm__ volatile(".byte 0x48, 0x0f, 0xae, 0x27\n\t" /* xsave64 (%rdi) */
         :
         : "D" (dest), "a" (eax), "d" (edx)
         : "memory");
#else
    __asm__ volatile(".byte 0x0f, 0xae, 0x27\n\t" /* xsave (%edi) */
         :
         : "D" (dest), "a" (eax), "d" (edx)
         : "memory");
#endif
}

static void hexdump_both(const uint8_t *data1, const uint8_t *data2, unsigned int size)
{
    unsigned int i, j, idx, bit_offset;
    bool is_empty;
    uint8_t d1, d2;
    uint32_t xstate_offset, xstate_relative, xstate_size;

    for (i = 0; i < size; i += 16) {
        printf("  %06x:", i);
        /* Detect empty lines */
        is_empty = true;
        for (j = 0; j < 16 && i + j < size; j++) {
            if (data1[i + j] || data2[i + j]) {
                is_empty = false;
                break;
            }
        }
        if (is_empty) {
            printf("                       (zeros)                      ");
        } else {
            /* Show the hex dump */
            for (j = 0; j < 16 && i + j < size; j++) {
                d1 = data1[i + j];
                d2 = data2[i + j];
                if (!(j % 4))
                    printf(" ");
                if (d1 == d2) {
                    printf(" %02x", d1);
                } else if (d1 == 0 && d2 == 0xff) {
                    printf(" ..");
                } else {
                    /* The 64-bit value at offset 0x200 (XSTATE_BV) has a specific semantic:
                     *     RFBM <- XCR0 AND EDX:EAX
                     *     OLD_BV <- XSTATE_BV field from XSAVE header
                     *     XSTATE_BV field in XSAVE header <- (OLD_BV AND ~RFBM) OR (XINUSE AND RFBM);
                     */
                    printf(" [%02x/%02x]", d1, d2);
                }
            }
            while (j < 16) {
                if (!(j % 4))
                    printf(" ");
                printf("   ");
                j++;
            }
        }

        /* Describe the line using XSAVE save area layout */
        is_empty = true;
        for (j = 0; j < (unsigned int)(sizeof(xstate_desc) / sizeof(xstate_desc[0])); j++) {
            xstate_offset = xstate_desc[j].offset;
            xstate_size = xstate_desc[j].size;
            if (xstate_offset <= i && i < xstate_offset + xstate_size) {
                xstate_relative = i - xstate_offset;
                if (j == 0) {
                    if (xstate_relative == 0) {
                        printf("  FCW, FSW, FTW, FOP, FPU IP, CS");
                    } else if (xstate_relative == 0x10) {
                        printf("  FPU DP, DS, (reserved), MXCSR, MXCSR_MASK");
                    } else {
                        idx = (xstate_relative - 0x20) >> 4;
                        printf("  ST%u MM%u (10 bytes)", idx, idx);
                    }
                    is_empty = false;
                } else if (j == 1) {
                    if (xstate_relative < 256) {
                        printf("  XMM%u (16 bytes)", xstate_relative >> 4);
                    } else {
                        printf("  (FXSAVE reserved)");
                    }
                    is_empty = false;
                } else if (j == 64) {
                    if (xstate_relative == 0) {
                        /* All the content is left as-is but the XSTATE_BV value */
                        printf("  XSTATE_BV, (XSTATE header reserved)");
                    } else {
                        printf("  (XSTATE header reserved)");
                    }
                    is_empty = false;
                } else if (j == 2 && xstate_offset > 0) {
                    printf("  YMM%u[255:128]", xstate_relative >> 4);
                    is_empty = false;
                } else if (j == 3 && xstate_offset > 0) {
                    idx = xstate_relative >> 4;
                    printf("  MPX BNDREG%u_lower, BNDREG%u_upper", idx, idx);
                    is_empty = false;
                } else if (j == 4 && xstate_offset > 0) {
                    if (xstate_relative == 0) {
                        printf("  MPX BNDCFGU, BNDSTATUS");
                    } else {
                        printf("  (MPX BNDCSR padding)");
                    }
                    is_empty = false;
                } else if (j == 5 && xstate_offset > 0) {
                    if (xstate_relative == 0) {
                        printf("  AVX-512 opmask (registers k0, k1)");
                    } else if (xstate_relative == 0x10) {
                        printf("  AVX-512 opmask (registers k2, k3)");
                    } else if (xstate_relative == 0x20) {
                        printf("  AVX-512 opmask (registers k4, k5)");
                    } else if (xstate_relative == 0x30) {
                        printf("  AVX-512 opmask (registers k6, k7)");
                    } else {
                        printf("  (unexpected AVX-512 opmask padding)");
                    }
                    is_empty = false;
                } else if (j == 6 && xstate_offset > 0) {
                    idx = xstate_relative >> 5;
                    bit_offset = 128 * ((xstate_relative >> 4) & 1) + 256;
                    printf("  AVX-512 ZMM%u[%u:%u]", idx, bit_offset + 127, bit_offset);
                    is_empty = false;
                } else if (j == 7 && xstate_offset > 0) {
                    idx = (xstate_relative >> 6) + 16;
                    bit_offset = 128 * ((xstate_relative >> 4) & 3);
                    printf("  AVX-512 ZMM%u[%u:%u]", idx, bit_offset + 127, bit_offset);
                    is_empty = false;
                } else if (j == 9 && xstate_offset > 0) {
                    printf("  PKRU");
                    is_empty = false;
                } else if (xstate_offset > 0) {
                    /* TODO add more data structures when the program is tested on compatible hardware */
                    printf("  (data for XCR0 bit %u)", j);
                }
            }
        }
        if (is_empty) {
            /* Show a ? if the data is defined (unmapped data?) */
            for (j = 0; j < 16 && i + j < size; j++) {
                if (data1[i + j] != 0 || data2[i + j] != 0xff) {
                    printf("  ?");
                    break;
                }
            }
        }
        printf("\n");
    }
}

int main(void)
{
    static uint8_t xsave_buffer1[4096] __attribute__ ((__aligned__(64)));
    static uint8_t xsave_buffer2[4096] __attribute__ ((__aligned__(64)));
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    uint64_t xcr0;
    bool is_active;
    unsigned int i, buflen, required_size;

    /* Check XSAVE CPUID leaf support */
    asm_cpuid(0, &eax, &ebx, &ecx, &edx);
    if (eax < 0xd) {
        printf("Unsupported CPU: CPUID leaf counts %u < 0xd\n", eax);
        return 0;
    }

    /* Check XSAVE bit in CPUID level 1 (ecx) */
    asm_cpuid(1, &eax, &ebx, &ecx, &edx);
    if (!(ecx & (1U << 26))) {
        printf("Unsupported CPU: no XSAVE support\n");
        return 0;
    }
    /* Check OSXSAVE bit in CPUID level 1 (ecx) */
    if (!(ecx & (1U << 27))) {
        printf("Unsupported CPU: disabled XSAVE support\n");
        return 0;
    }

    /* Get XSAVE states */
    ecx = 0;
    eax = edx = 0xffffffffU;
    asm_cpuid(0xd, &eax, &ebx, &ecx, &edx);
    printf("CPUID 0xd.0:\n");
    printf("  (edx:eax) XSAVE processor supported state mask: %#" PRIx64 "\n", eax + ((uint64_t)edx << 32));
    printf("  (ecx) required size of XSAVE for all supported components: %u = %#x bytes\n", ecx, ecx);
    printf("  (ebx) required size of XSAVE for all enabled components: %u = %#x bytes\n", ebx, ebx);
    required_size = ebx;

    xcr0 = xgetbv(0);
    printf("(XCR0) XSAVE OS supported state mask: %#" PRIx64 "\n", xcr0);
    for (i = 0; i < 64; i++) {
        is_active = !!((xcr0 >> i) & 1);
        if (xstate_desc[i].desc) {
            printf("  [%2u] %c%s\n", i, is_active ? '+' : '-', xstate_desc[i].desc);
        } else if (is_active) {
            printf("  [%2u] +?\n", i);
        }
        /* Get offsets and sizes of components with CPUID */
        if (is_active) {
            if (i >= 2) {
                ecx = i;
                asm_cpuid(0xd, &eax, &ebx, &ecx, &edx);
            } else {
                /* FPU and SSE regions have static offsets and sizes */
                eax = xstate_desc[i].size;
                ebx = xstate_desc[i].offset;
                assert(ebx < required_size && ebx + eax <= required_size);
            }
            printf("        %04x..%04x (%u bytes at offset %u)\n",
                   ebx, ebx + eax - 1, eax, ebx);
            if (xstate_desc[i].size != eax) {
                fprintf(stderr, "Unexpected size for component %u: %u instead of %u\n",
                        i, eax, xstate_desc[i].size);
                return 1;
            }
            xstate_desc[i].offset = ebx;
        }
    }

    /* Try XSAVE */
    assert(sizeof(xsave_buffer1) == sizeof(xsave_buffer2));
    buflen = (unsigned int)sizeof(xsave_buffer1);
    if ((size_t)required_size > sizeof(xsave_buffer1)) {
        fprintf(stderr, "XSAVE state too large for internal buffer!\n");
        return 1;
    }
    /* Poison the buffers and run xsave */
    memset(xsave_buffer1, 0, sizeof(xsave_buffer1));
    memset(xsave_buffer2, 0xff, sizeof(xsave_buffer2));
    xsave(xsave_buffer1, xcr0);
    xsave(xsave_buffer2, xcr0);
    for (i = required_size; i < buflen; i++) {
        if (xsave_buffer1[i] != 0 || xsave_buffer2[i] != 0xff) {
            fprintf(stderr, "XSAVE overflow: %#x >= %#x\n", i, required_size);
            return 1;
        }
    }

    /* Dump the result */
    printf("\nCurrent processor extended states:\n");
    hexdump_both(xsave_buffer1, xsave_buffer2, required_size);

    return 0;
}
