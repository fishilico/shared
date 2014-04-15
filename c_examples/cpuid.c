/**
 * Display cpuid's information
 */
#include <stdint.h>
#include <stdio.h>
#include "cpuid_enum.h"

#if defined __i386__ || defined __x86_64__

static void print_escaped_ascii(const char *prefix, const char *text)
{
    const char *current;
    if (prefix) {
        printf("%s: ", prefix);
    }
    for (current = text; *current; current++) {
        const char c = *current;
        if (c < 32 || c >= 127) {
            /* Print text..(current-1) */
            while (text < current) {
                size_t count = fwrite(text, 1, current - text, stdout);
                if (!count) {
                    fprintf(stderr, "fwrite error to stdout\n");
                    return;
                }
                text += count;
            }
            printf("\\x%02x", (unsigned)(unsigned char)c);
            text++;
        }
    }
    printf("%s\n", text);
}

static void asm_cpuid(uint32_t code, uint32_t *peax, uint32_t *pebx, uint32_t *pecx, uint32_t *pedx)
{
#if defined __i386__ && defined __GNUC__ && defined __PIC__
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

static void print_features(const char *name, uint32_t bits, const char* const cpuidstr[32])
{
    int i;
    printf("%s:", name);
    for (i = 0; i < 32; i++) {
        if (cpuidstr[i]) {
            printf(" %c%s", bits & (1 << i) ? '+' : '-', cpuidstr[i]);
        }
    }
    printf("\n");
}

int main()
{
    char vendor_str[13] = {0};
    uint32_t max_code, max_extcode;
    int i;

    /* Convert str to an array of 32-bits values */
    uint32_t *data = (uint32_t*)vendor_str;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    /* CPUID 0: get vendor string */
    asm_cpuid(0, &max_code, &data[0], &data[2], &data[1]);
    vendor_str[12] = 0;
    print_escaped_ascii("CPUID vendor string", vendor_str);
    printf("Max CPUID code: %u\n", max_code);

    /* CPUID 1: get features */
    asm_cpuid(1, &eax, &ebx, &ecx, &edx);
    print_features("Features 1.edx", edx, cpuidstr_1_edx);
    print_features("Features 1.ecx", ecx, cpuidstr_1_ecx);
    if (max_code >= 7) {
        ecx = 0;
        asm_cpuid(7, &eax, &ebx, &ecx, &edx);
        if (ebx) {
            print_features("Features 7:0.ebx", ebx, cpuidstr_7_ebx);
        }
    }

    /* CPUID 0x80000000: extended features */
    asm_cpuid(0x80000000, &max_extcode, &ebx, &ecx, &edx);
    printf("Maximum extended function: 0x%08x\n", max_extcode);
    if (max_extcode >= 0x80000001) {
        asm_cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
        print_features("Features ext1.edx", edx, cpuidstr_ext1_edx);
        print_features("Features ext1.ecx", ecx, cpuidstr_ext1_ecx);
    }
    if (max_extcode >= 0x80000004) {
        /* Processor Brand String */
        char brand_str[256], *start_brand_str;
        for (i = 0; i < 3; i++) {
            data = (uint32_t*)(brand_str + 16 * i);
            asm_cpuid(0x80000002 + i, &data[0], &data[1], &data[2], &data[3]);
        }
        brand_str[16*i] = 0;
        start_brand_str = brand_str;
        while (*start_brand_str == ' ') {
            start_brand_str ++;
        }
        print_escaped_ascii("Processor Brand String", start_brand_str);
    }
    return 0;
}

#else
int main()
{
    fprintf(stderr, "cpuid not implemented on this architecture :(\n");
    return 255;
}
#endif
