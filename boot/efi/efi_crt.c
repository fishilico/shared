/**
 * Custom EFI C Runtime for ELF files
 */
#include <elf.h>
#include "efi.h"

#if defined __x86_64__
#    define DEFINE_ELF_STRUCT(name) typedef Elf64_##name Elf_##name
#elif defined  __i386__
#    define DEFINE_ELF_STRUCT(name) typedef Elf32_##name Elf_##name
#else
#    error Unsupported architecture
#endif
DEFINE_ELF_STRUCT(Dyn);

extern const Elf_Dyn *_DYNAMIC;

EFI_SYSTEM_TABLE *ST;
EFI_BOOT_SERVICES *BS;
EFI_RUNTIME_SERVICES *RT;

/**
 * Write a string to the output interface
 */
void output_string(const CHAR16 *text)
{
    efi_call2(ST->ConOut->OutputString, ST->ConOut, text);
}

/**
 * Initialize global variables and call efi_main
 */
static __attribute__ ((used))
EFI_STATUS crt_efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    unsigned int i;

    /* Initialize global state */
    ST = SystemTable;
    BS = SystemTable->BootServices;
    RT = SystemTable->RuntimeServices;

    /* Check that the file has no relocations in its dynamic section
     * It is possible to use "readelf --dynamic" to dump the content of the dynamic section
     */
    for (i = 0; _DYNAMIC[i].d_tag != DT_NULL; i++) {
        switch (_DYNAMIC[i].d_tag) {
            case DT_REL:
            case DT_RELSZ:
            case DT_RELENT:
                output_string(L"Error: found REL relocation. Aborting\n");
                return EFI_LOAD_ERROR;

            case DT_RELA:
            case DT_RELASZ:
            case DT_RELAENT:
                output_string(L"Error: found RELA relocation. Aborting\n");
                return EFI_LOAD_ERROR;
        }
    }

    return efi_main(ImageHandle, SystemTable);
}

__asm__ (
"    .text\n"
"    .globl _start\n"
"    .hidden _start\n"
"    .type _start, @function\n"
"_start:\n"
#if defined __x86_64__
"    subq $8, %rsp\n"
"    movq %rcx, %rdi\n" /* image */
"    movq %rdx, %rsi\n" /* systab */
"    call crt_efi_main\n"
"    addq $8, %rsp\n"
"    ret\n"
#elif defined __i386__
"    pushl %ebp\n"
"    movl %esp, %ebp\n"
"    pushl 12(%ebp)\n" /* image */
"    pushl 8(%ebp)\n" /* systab */
"    call crt_efi_main\n"
"    movl %ebp, %esp\n"
"    popl %ebp\n"
"    ret\n"
#else
#    error Unsupported architecture
#endif
);

/* Add a fake base-reloc entry to make UEFI loader think it is a relocatable executable.
 * This is a IMAGE_BASE_RELOCATION structure, registered at entry IMAGE_DIRECTORY_ENTRY_BASERELOC
 * of the PE data directory.
 *
 *    typedef struct _IMAGE_BASE_RELOCATION {
 *        DWORD VirtualAddress;
 *        DWORD SizeOfBlock;
 *    } IMAGE_BASE_RELOCATION;
 *
 * Dump with: winedump -j reloc dump BOOTX64.efi
 */
__asm__ (
"    .data\n"
"    .hidden _crt_dummy_reloc\n"
"_crt_dummy_reloc: .long 0\n"

#if defined __x86_64__
"    .section .reloc, \"a\"\n"
"    .hidden _crt_base_reloc\n"
"_crt_base_reloc:\n"
"    .long _crt_dummy_reloc - _crt_base_reloc\n" /* RVA */
"    .long 10\n" /* SizeOfBlock: 8 of structure + 2 of data */
"    .word 0\n" /* IMAGE_REL_BASED_ABSOLUTE << 12 | 0 */
#elif defined __i386__
"    .section .reloc\n"
"    .long _crt_dummy_reloc\n" /* RVA */
"    .long 10\n" /* SizeOfBlock: 8 of structure + 2 of data */
"    .word 0\n" /* IMAGE_REL_BASED_ABSOLUTE << 12 | 0 */
#else
#    error Unsupported architecture
#endif
);
