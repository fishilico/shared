/**
 * Dump UEFI environment variables
 */
#include "efi.h"

#define EFI_VARIABLE_NON_VOLATILE               0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS         0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS             0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD      0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x00000010

/**
 * Get an variable by its name and vendor GUID
 */
static VOID * get_efi_variable(const CHAR16 *name, const EFI_GUID *vendor, UINTN *size, UINT32 *attributes)
{
    EFI_STATUS status;
    UINT8 localbuffer[1024];
    UINTN bufsize = sizeof(localbuffer), i;
    UINT8 *buffer = NULL;

    /* Find out how much size is needed and allocate accordingly in pool */
    status = efi_call5(RT->GetVariable, name, vendor, attributes, &bufsize, localbuffer);
    if (status == EFI_BUFFER_TOO_SMALL) {
        buffer = pool_alloc(bufsize);
        if (buffer) {
            status = efi_call5(RT->GetVariable, name, vendor, attributes, &bufsize, buffer);
        }
    } else if (!EFI_ERROR(status) && bufsize <= sizeof(localbuffer)) {
        buffer = pool_alloc(bufsize);
        if (buffer) {
            for (i = 0; i < bufsize; i++) {
                buffer[i] = localbuffer[i];
            }
        }
    }

    if (EFI_ERROR(status)) {
        print(L"Error in GetVariable\n");
        if (buffer) {
            pool_free(buffer);
        }
    }
    if (size) {
        *size = bufsize;
    }
    return buffer;
}

/**
 * Format a GUID into a string
 *
 * printf format: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x -> length 36
 */
#define format_hexnum(type, num, output) \
    do { \
        int _i; \
        type _n = (num); \
        CHAR16 *_output = (output); \
        for (_i = 2 * sizeof(_n) - 1; _i >= 0; _i--) { \
            type _digit = _n & 0xf; \
            _n = _n >> 4; \
            _output[_i] = ((_digit < 10) ? L'0' : L'a' - 10) + _digit; \
        } \
    } while (0)
static void format_guid(const EFI_GUID *guid, CHAR16 *str)
{
    format_hexnum(UINT32, guid->Data1, str);
    str[8] = L'-';
    format_hexnum(UINT16, guid->Data2, str + 9);
    str[13] = L'-';
    format_hexnum(UINT16, guid->Data3, str + 14);
    str[18] = L'-';
    format_hexnum(UINT8, guid->Data4[0], str + 19);
    format_hexnum(UINT8, guid->Data4[1], str + 21);
    str[23] = L'-';
    format_hexnum(UINT8, guid->Data4[2], str + 24);
    format_hexnum(UINT8, guid->Data4[3], str + 26);
    format_hexnum(UINT8, guid->Data4[4], str + 28);
    format_hexnum(UINT8, guid->Data4[5], str + 30);
    format_hexnum(UINT8, guid->Data4[6], str + 32);
    format_hexnum(UINT8, guid->Data4[7], str + 34);
    str[36] = L'\0';
}

EFI_STATUS efi_main(EFI_HANDLE image __attribute__ ((unused)), EFI_SYSTEM_TABLE *systab __attribute__ ((unused)))
{
    EFI_STATUS status;
    CHAR16 name[256] = L"", *value, formatted_guid[37];
    EFI_GUID vendor = {0};
    UINTN size;
    UINT32 attributes;

    print(L"GUID Name Attributes:\n");

    for (;;) {
        size = sizeof(name);
        status = efi_call3(RT->GetNextVariableName, &size, name, &vendor);
        if (status == EFI_BUFFER_TOO_SMALL) {
            print(L"Error: buffer for variable name is too small.\n");
            break;
        } else if (status != EFI_SUCCESS)
            break;

        attributes = 0;
        value = (CHAR16 *)get_efi_variable(name, &vendor, &size, &attributes);
        if (value) {
            format_guid(&vendor, formatted_guid);
            print(formatted_guid);
            print(L" ");
            print(name);
            /* TODO: size */
            if (attributes & EFI_VARIABLE_NON_VOLATILE) {
                print(L" NonVolatile");
            }
            if (attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) {
                print(L" BSAccess");
            }
            if (attributes & EFI_VARIABLE_RUNTIME_ACCESS) {
                print(L" RTAccess");
            }
            if (attributes & EFI_VARIABLE_HARDWARE_ERROR_RECORD) {
                print(L" HWErrRecord");
            }
            if (attributes & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) {
                print(L" AuthWrAccess");
            }
            print(L"\n");
            pool_free(value);
        }
    }
    waitkey(TRUE);
    return EFI_SUCCESS;
}
