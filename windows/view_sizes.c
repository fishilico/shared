/**
 * Print the size of the standard types, with the current processor architecture
 */
#include "common.h"

static void print_machine(void)
{
    SYSTEM_INFO siSysInfo;
    LPCTSTR machine;
    GetSystemInfo(&siSysInfo);
    switch (siSysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            machine = _T("x86_64");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            machine = _T("arm");
            break;
        case PROCESSOR_ARCHITECTURE_IA64:
            machine = _T("ia64");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            machine = _T("x86");
            break;
        case PROCESSOR_ARCHITECTURE_UNKNOWN:
            machine = _T("unknown");
            break;
        default:
            machine = _T("?? (not implemented value)");
    }
    _tprintf(_T("Machine: %s\n"), machine);
}

static void _print_type_size(const char *name, size_t size)
{
    _tprintf(_T(" * sizeof(%11" PRIsA ") = %2lu %s (%3lu bits)\n"),
             name, (unsigned long)size, (size == 1) ? _T("byte ") : _T("bytes"), (unsigned long)size * 8);
}

#define print_type_size(type) _print_type_size(#type, sizeof(type))

int _tmain(void)
{
    print_machine();
    _tprintf(_T("Standard C integer types:\n"));
    print_type_size(CHAR);
    print_type_size(WCHAR);
    print_type_size(SHORT);
    print_type_size(INT);
    print_type_size(LONG);
    print_type_size(LONGLONG);
    _tprintf(_T("\nOther integer types:\n"));
    print_type_size(BOOL);
    print_type_size(TCHAR);
    print_type_size(SIZE_T);
    print_type_size(INT_PTR);
    print_type_size(WPARAM);
    print_type_size(LPARAM);
    print_type_size(LRESULT);
    _tprintf(_T("\nFixed-width integer types:\n"));
    print_type_size(BYTE);
    print_type_size(WORD);
    print_type_size(DWORD);
    /* print_type_size(QWORD); */
    _tprintf(_T("\nFloat types:\n"));
    print_type_size(FLOAT);
    _tprintf(_T("\nPointer types:\n"));
    print_type_size(PVOID);
    print_type_size(HANDLE);
    print_type_size(LPSTR);
    return 0;
}
