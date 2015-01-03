/**
 * Display "Hello, world!" using EFI API, but without gnu-efi library.
 *
 * Here is an equivalent program with gnu-efi, compiled with this added to Makefile:
 * * CFLAGS += -I/usr/include/efi -I/usr/include/efi/$(ARCH) -I/usr/include/efi/protocol
 * * LIBS += /usr/lib/crt0-efi-x86_64.o -L /usr/lib -lefi -lgnuefi
 *
#include <efi.h>
#include <efilib.h>

EFI_STATUS efi_main(EFI_HANDLE image __attribute__ ((unused)), EFI_SYSTEM_TABLE *systab)
{
    UINTN EventIndex;
    EFI_INPUT_KEY key;

    InitializeLib(image, systab);
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Hello, world!\nPress a key to continue.\n");
    uefi_call_wrapper(BS->WaitForEvent, 3, 1, &ST->ConIn->WaitForKey, &EventIndex);
    uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &key);
    return EFI_SUCCESS;
}
 */
#include "efi.h"

#if defined __x86_64__
#    define ARCH_DESC "x86_64"
#elif defined  __i386__
#    define ARCH_DESC "ia32"
#elif defined  __arm__
#    define ARCH_DESC "arm"
#else
#    error Unsupported architecture
#    define ARCH_DESC "unknown"
#endif

EFI_STATUS efi_main(EFI_HANDLE image __attribute__ ((unused)), EFI_SYSTEM_TABLE *systab)
{
    UINTN EventIndex;
    EFI_INPUT_KEY key;

    efi_call2(
        systab->ConOut->OutputString,
        systab->ConOut,
        L"Hello, world! I'm running on a " ARCH_DESC " system!\n"
        "Press a key to continue.\n");

    efi_call3(
        systab->BootServices->WaitForEvent,
        1,
        &systab->ConIn->WaitForKey,
        &EventIndex);

    efi_call2(
        systab->ConIn->ReadKeyStroke,
        systab->ConIn,
        &key);

    return EFI_SUCCESS;
}
