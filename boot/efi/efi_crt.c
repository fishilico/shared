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
EFI_MEMORY_TYPE PoolAllocationType;

EFI_GUID LoadedImageProtocol = {0x5B1B31A1, 0x9562, 0x11d2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};

/**
 * Implement some routines needed by the compiler
 */
void *memset(void *s, int c, UINTN n)
{
    UINT8 *bytes = s;

    while (n--) {
        *(bytes++) = c;
    }
    return s;
}

/**
 * Write a string to the output interface
 */
void print(const CHAR16 *text)
{
    efi_call2(ST->ConOut->OutputString, ST->ConOut, text);
}

/**
 * Wait for a keypress
 */
void waitkey(BOOLEAN message)
{
    UINTN EventIndex;
    EFI_INPUT_KEY key;

    if (message) {
        print(L"Press a key to continue.\n");
    }

    efi_call3(BS->WaitForEvent, 1, &ST->ConIn->WaitForKey, &EventIndex);
    efi_call2(ST->ConIn->ReadKeyStroke, ST->ConIn, &key);
}

/**
 * Allocate memory in current pool
 */
void * pool_alloc(UINTN size)
{
    void *buffer = NULL;
    EFI_STATUS status;

    status = efi_call3(BS->AllocatePool, PoolAllocationType, size, &buffer);
    if (EFI_ERROR(status) || !buffer) {
        print(L"Unable to allocate enough bytes in pool\n");
        return NULL;
    }
    return buffer;
}

/**
 * Free allocated memory
 */
void pool_free(void *buffer)
{
    efi_call1(BS->FreePool, buffer);
}

/**
 * Initialize global variables and call efi_main
 */
static __attribute__ ((used))
EFI_STATUS crt_efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    unsigned int i;
    EFI_STATUS status;
    EFI_LOADED_IMAGE *LoadedImage;

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
                print(L"Error: found REL relocation. Aborting\n");
                return EFI_LOAD_ERROR;

            case DT_RELA:
            case DT_RELASZ:
            case DT_RELAENT:
                print(L"Error: found RELA relocation. Aborting\n");
                return EFI_LOAD_ERROR;
        }
    }

    /* Initialize PoolAllocationType */
    if (ImageHandle) {
        status = efi_call3(BS->HandleProtocol, ImageHandle,
                           &LoadedImageProtocol, (VOID **)&LoadedImage);
        if (!EFI_ERROR(status)) {
            PoolAllocationType = LoadedImage->ImageDataType;
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
