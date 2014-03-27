/**
 * Display cpuid's information
 */
#include <stdint.h>
#include <stdio.h>

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
        :"0"(code));
#else
    __asm__ volatile ("cpuid"
        :"=a"(*peax), "=b"(*pebx), "=c"(*pecx), "=d"(*pedx)
        :"0"(code));
#endif
}

int main()
{
    char vendor_str[13];
    unsigned int max_code;
    int i;

    /* Convert str to an array of 32-bits values */
    uint32_t *data = (uint32_t*)vendor_str;
    uint32_t eax, ebx, ecx, edx;

    /* CPUID 0: get vendor string */
    asm_cpuid(0, &max_code, &data[0], &data[2], &data[1]);
    vendor_str[12] = 0;
    print_escaped_ascii("CPUID vendor string", vendor_str);
    printf("Max CPUID code: %u\n", max_code);

    /* CPUID 1: get features */
    asm_cpuid(1, &eax, &ebx, &ecx, &edx);
    printf("Features:");
#define print_cpufeat(reg, bit, name) \
    printf(" %c" name, e##reg##x & (1 << bit) ? '+' : '-')
    /* List of features: http://wiki.osdev.org/CPUID */
    print_cpufeat(d, 0, "fpu");
    print_cpufeat(d, 1, "vme");
    print_cpufeat(d, 2, "de");
    print_cpufeat(d, 3, "pse");
    print_cpufeat(d, 4, "tsc");
    print_cpufeat(d, 5, "msr");
    print_cpufeat(d, 6, "pae");
    print_cpufeat(d, 7, "mce");
    print_cpufeat(d, 8, "cx8");
    print_cpufeat(d, 9, "apic");
    print_cpufeat(d, 11, "sep");
    print_cpufeat(d, 12, "mtrr");
    print_cpufeat(d, 13, "pge");
    print_cpufeat(d, 14, "mca");
    print_cpufeat(d, 15, "cmov");
    print_cpufeat(d, 16, "pat");
    print_cpufeat(d, 17, "pse36");
    print_cpufeat(d, 18, "psn");
    print_cpufeat(d, 19, "clflush");
    print_cpufeat(d, 21, "dtes");
    print_cpufeat(d, 22, "acpi");
    print_cpufeat(d, 23, "mmx");
    print_cpufeat(d, 24, "fxsr");
    print_cpufeat(d, 25, "sse");
    print_cpufeat(d, 26, "sse2");
    print_cpufeat(d, 27, "ss");
    print_cpufeat(d, 28, "htt");
    print_cpufeat(d, 29, "tm1");
    print_cpufeat(d, 30, "ia64");
    print_cpufeat(d, 31, "pbe");

    print_cpufeat(c, 0, "sse3");
    print_cpufeat(c, 1, "pclmulqdq");
    print_cpufeat(c, 2, "dtes64");
    print_cpufeat(c, 3, "monitor");
    print_cpufeat(c, 4, "ds_cpl");
    print_cpufeat(c, 5, "vmx");
    print_cpufeat(c, 6, "smx");
    print_cpufeat(c, 7, "est");
    print_cpufeat(c, 8, "tm2");
    print_cpufeat(c, 9, "ssse3");
    print_cpufeat(c, 10, "cid");
    print_cpufeat(c, 12, "fma");
    print_cpufeat(c, 13, "cx16");
    print_cpufeat(c, 14, "etprd");
    print_cpufeat(c, 15, "pdcm");
    print_cpufeat(c, 18, "dca");
    print_cpufeat(c, 19, "sse4_1");
    print_cpufeat(c, 20, "sse4_2");
    print_cpufeat(c, 21, "x2apic");
    print_cpufeat(c, 22, "movbe");
    print_cpufeat(c, 23, "popcnt");
    print_cpufeat(c, 25, "aes");
    print_cpufeat(c, 26, "xsave");
    print_cpufeat(c, 27, "osxsave");
    print_cpufeat(c, 28, "avx");
    printf("\n");

    /* CPUID 0x80000000: extended features */
    asm_cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    printf("Maximum extended function: 0x%08x\n", eax);
    if (eax >= 0x80000004) {
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
