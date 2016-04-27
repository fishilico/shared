/**
 * Display cpuid information on x86 cpus
 *
 * gcc defines __cpuid and __cpuid_count macros in cpuid.h:
 * https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;a=blob;f=gcc/config/i386/cpuid.h
 * and glibc uses these macros to retrieve CPU cache information:
 * https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/cacheinfo.c
 *
 * Some information about x86 flags can also be found on Wikipedia:
 * http://en.wikipedia.org/wiki/CPUID
 *
 * The official documentation is Intel 64 and IA-32 Architectures Software Developer Manuals
 *   http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html
 *   in Volume 2A: CPUID instruction
 *
 * On Linux, CPU flags are available in /proc/cpuinfo:
 *     grep '^flags' /proc/cpuinfo |uniq
 * and in the auxiliary vector:
 *     LD_SHOW_AUXV=1 /bin/true | grep AT_HWCAP
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "x86-cpuid_enum.h"

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
                size_t count = fwrite(text, 1, (size_t)(current - text), stdout);
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

static void print_features(const char *name, uint32_t bits, const char *const cpuidstr[32])
{
    unsigned int i;
    printf("%s:\n", name);
    for (i = 0; i < 32; i++) {
        if (cpuidstr[i]) {
            printf("  [%2u] %c%s\n", i, (bits & (1U << i)) ? '+' : '-', cpuidstr[i]);
        } else if (bits & (1U << i)) {
            printf("  [%2u] +?\n", i);
        }
    }
}

int main(void)
{
    uint32_t vendor_data[4] = { 0 };
    uint32_t max_code, max_extcode;

    /* Convert str to an array of 32-bits values */
    uint32_t *data;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    add_manual_cpuid_str();

    /* CPUID 0: get vendor string */
    asm_cpuid(0, &max_code, &vendor_data[0], &vendor_data[2], &vendor_data[1]);
    vendor_data[3] = 0;
    print_escaped_ascii("CPUID vendor string", (char *)vendor_data);
    if (vendor_data[0] == 0x756e6547 && vendor_data[1] == 0x49656e69 && vendor_data[2] == 0x6c65746e) {
        printf(" (This is genuine Intel)\n");
    } else if (vendor_data[0] == 0x68747541 && vendor_data[1] == 0x69746e65 && vendor_data[2] == 0x444d4163) {
        printf(" (This is authentic AMD)\n");
    }
    printf("Max CPUID code: %u\n", max_code);

    if (max_code >= 1) {
        /* CPUID 1: get family, model and features
         * Family is eax[8:11] + eax[20:27]
         * Model is (eax[16:19] << 4) + eax[4:7]
         */
        asm_cpuid(1, &eax, &ebx, &ecx, &edx);
        printf("1.eax = %#x: CPU family %u, model %u\n", eax,
               ((eax >> 8) & 0xf) + ((eax >> 20) & 0xff),
               ((eax >> 4) & 0xf) + ((eax >> 12) & 0xf0));
        print_features("Features 1.edx", edx, cpuidstr_1_edx);
        print_features("Features 1.ecx", ecx, cpuidstr_1_ecx);
    }
    if (max_code >= 6) {
        asm_cpuid(6, &eax, &ebx, &ecx, &edx);
        if (eax) {
            print_features("Features 6.eax", eax, cpuidstr_6_eax);
        }
        if (ecx) {
            print_features("Features 6.ecx", ecx, cpuidstr_6_ecx);
        }
    }
    if (max_code >= 7) {
        ecx = 0;
        asm_cpuid(7, &eax, &ebx, &ecx, &edx);
        if (ebx) {
            print_features("Features 7:0.ebx", ebx, cpuidstr_7_ebx);
        }
        if (ecx) {
            print_features("Features 7:0.ecx", ecx, cpuidstr_7_ecx);
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
        uint32_t brand_str[64];
        char *start_brand_str;
        unsigned int i;
        for (i = 0; i < 3; i++) {
            data = (brand_str + 4 * i);
            asm_cpuid(0x80000002 + i, &data[0], &data[1], &data[2], &data[3]);
        }
        start_brand_str = (char *)brand_str;
        start_brand_str[sizeof(brand_str) - 1] = '\0';
        while (*start_brand_str == ' ') {
            start_brand_str++;
        }
        print_escaped_ascii("Processor Brand String (ext2..4)", start_brand_str);
    }
    if (max_extcode >= 0x80000007) {
        asm_cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
        print_features("Features ext7.edx", edx, cpuidstr_ext7_edx);
    }
    return 0;
}
