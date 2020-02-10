/**
 * List the command lines of the currently running processes using a remote thread.
 *
 * This works because kernel32.dll is always mapped at the same address in
 * every process.
 * A more stable way of doing this is using WMI, for example in PowerShell:
 *
 *     Get-WmiObject -query 'SELECT ProcessId, Name, CommandLine from Win32_Process' |
 *       Format-List -Property ('ProcessId','Name','CommandLine')
 *
 * API documentation:
 *  HANDLE WINAPI CreateRemoteThread(
 *      IN HANDLE hProcess,
 *      IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
 *      IN SIZE_T dwStackSize,
 *      IN LPTHREAD_START_ROUTINE lpStartAddress,
 *      IN LPVOID lpParameter,
 *      IN DWORD dwCreationFlags,
 *      OUT LPDWORD lpThreadId
 *  );
 */
#include "common.h"
#include <inttypes.h>
#include <tlhelp32.h>

typedef DWORD (WINAPI * pfnNtQueryInformationProcess_t) (
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

/* PROCESS_BASIC_INFORMATION structure */
typedef struct _PROCESS_BASIC_INFORMATION_FOR_PEB {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_FOR_PEB;

typedef struct _UNICODE_STRING_FOR_CMDLINE {
    USHORT Length; /* Length in bytes */
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_FOR_CMDLINE;

/* Define offsets according to the architecture */
#if defined(__x86_64)
#    define PEB_offset_ProcessParameters 0x20
#    define RTL_USER_PROCESS_PARAMETERS_offset_CommandLine 0x70
#elif defined(__i386__)
#    define PEB_offset_ProcessParameters 0x10
#    define RTL_USER_PROCESS_PARAMETERS_offset_CommandLine 0x40
#else
#    warning Unsupported architecture
#endif

int _tmain(void)
{
    HMODULE hKernel, hNtdll;
    LPTHREAD_START_ROUTINE lpfctGetCmdLine;
    pfnNtQueryInformationProcess_t pfnNtQueryInformationProcess;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hKernel = GetModuleHandle(_T("kernel32.dll"));
    if (!hKernel) {
        print_winerr(_T("GetModuleHandle(kernel32.dll)"));
        return 1;
    }
    lpfctGetCmdLine = (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(hKernel, "GetCommandLineW");
    if (!lpfctGetCmdLine) {
        print_winerr(_T("GetProcAddress(kernel32, GetCommandLineW)"));
        return 1;
    }
    _tprintf(_T("Using kernel32@%p->GetCommandLineW@%p\n"), hKernel, (void *)lpfctGetCmdLine);

    hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (!hKernel) {
        print_winerr(_T("GetModuleHandle(ntdll.dll)"));
        return 1;
    }
    pfnNtQueryInformationProcess =
        (pfnNtQueryInformationProcess_t) (void *)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pfnNtQueryInformationProcess) {
        print_winerr(_T("GetProcAddress(ntdll, NtQueryInformationProcess)"));
        return 1;
    }

    /* Take a snapshot of processes to enumerate them */
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        print_winerr(_T("CreateToolhelp32Snapshot(Process)"));
        return 1;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        print_winerr(_T("Process32First"));
        CloseHandle(hProcessSnap);
        return 1;
    }
    do {
        HANDLE hModuleSnap, hProcess, hThread;
        MODULEENTRY32 me32;
        DWORD dwRetAddr, dwStatus;
        WCHAR wszCmdLine[MAX_PATH * 8];
        SIZE_T cbRead;
        ULONG length = 0;
        PROCESS_BASIC_INFORMATION_FOR_PEB ProcBasicInfo;
        UINT_PTR ppTargetUserProcessParameters;
        UINT_PTR pTargetUserProcessParameters = 0;
        UNICODE_STRING_FOR_CMDLINE ustrTargetCommandLine = { 0, 0, NULL };
        UINT_PTR pwszTargetCommandLine;

        /* Skip PID 0 [System Process] */
        if (pe32.th32ProcessID == 0) {
            _tprintf(_T("PID %lu: %s\n"), pe32.th32ProcessID, pe32.szExeFile);
            if (_tcscmp(pe32.szExeFile, _T("[System Process]"))) {
                _ftprintf(stderr, _T("PID %lu (%s): Unexpected PID 0 process name\n"),
                          pe32.th32ProcessID, pe32.szExeFile);
                /* Make this error fatal in order to detect such a situation */
                return 1;
            }
            continue;
        }

        /* 32-bit applications fail to inject code into 64-bit ones and vice-versa.
         * Such issue can be detected when attempting to enumerate modules.
         */
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
        if (hModuleSnap == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_NOACCESS || GetLastError() == ERROR_PARTIAL_COPY) {
                /* This happens if I use 32 bits and target uses 64 bits */
                _ftprintf(stderr, _T("PID %lu (%s): Unable to enumerate modules\n"),
                          pe32.th32ProcessID, pe32.szExeFile);
            } else {
                _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
                print_winerr(_T("CreateToolhelp32Snapshot(Module)"));
            }
            continue;
        }
        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32)) {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                /* This happens if I use 64 bits and target uses 32 bits */
                _tprintf(_T("PID %lu (%s): Unable to enumerate modules\n"), pe32.th32ProcessID, pe32.szExeFile);
            } else {
                print_winerr(_T("Module32First"));
            }
            CloseHandle(hModuleSnap);
            continue;
        }
        CloseHandle(hModuleSnap);

        /* Open the target process */
        hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            0, pe32.th32ProcessID);
        if (!hProcess) {
            if (GetLastError() != ERROR_ACCESS_DENIED) {
                _ftprintf(stderr, _T("PID %lu (%s): access error: "), pe32.th32ProcessID, pe32.szExeFile);
                print_winerr(_T("OpenProcess"));
            }
            continue;
        }

        /* Retrieve the PEB using ProcessBasicInformation = 0 */
        ZeroMemory(&ProcBasicInfo, sizeof(ProcBasicInfo));
        dwStatus = (*pfnNtQueryInformationProcess)(hProcess, 0, &ProcBasicInfo, sizeof(ProcBasicInfo), &length);
        if (dwStatus) {
            _ftprintf(stderr, _T("PID %lu (%s): NtQueryInformationProcess: error %#lx\n"),
                      pe32.th32ProcessID, pe32.szExeFile, dwStatus);
            CloseHandle(hProcess);
            continue;
        }
        /* Get PEB->ProcessParameters (PRTL_USER_PROCESS_PARAMETERS) */
        ppTargetUserProcessParameters = ((UINT_PTR)ProcBasicInfo.PebBaseAddress) + PEB_offset_ProcessParameters;
        cbRead = 0;
        if (!ReadProcessMemory(hProcess,
                               (PVOID)ppTargetUserProcessParameters,
                               &pTargetUserProcessParameters,
                               sizeof(pTargetUserProcessParameters),
                               &cbRead)) {
            _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
            print_winerr(_T("ReadProcessMemory(PEB->ProcessParameters)"));
            CloseHandle(hProcess);
            continue;
        }
        assert(cbRead == sizeof(pTargetUserProcessParameters));

        /* Get ProcessParameters->CommandLine (UNICODE_STRING) */
        cbRead = 0;
        if (!ReadProcessMemory(hProcess,
                               (PVOID)(pTargetUserProcessParameters + RTL_USER_PROCESS_PARAMETERS_offset_CommandLine),
                               &ustrTargetCommandLine,
                               sizeof(ustrTargetCommandLine),
                               &cbRead)) {
            _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
            print_winerr(_T("ReadProcessMemory(ProcessParameters->CommandLine)"));
            CloseHandle(hProcess);
            continue;
        }
        assert(cbRead == sizeof(UNICODE_STRING_FOR_CMDLINE));

        /* Read the command line */
        if (ustrTargetCommandLine.Length >= sizeof(wszCmdLine)) {
            _ftprintf(stderr, _T("PID %lu (%s): command line is too large (%u bytes)\n"),
                      pe32.th32ProcessID, pe32.szExeFile, ustrTargetCommandLine.Length);
            /* This is a fatal error: need to increase the size of the buffer */
            return 1;
        }
        ZeroMemory(wszCmdLine, sizeof(wszCmdLine));
        cbRead = 0;
        if (!ReadProcessMemory(hProcess,
                               ustrTargetCommandLine.Buffer,
                               &wszCmdLine,
                               ustrTargetCommandLine.Length,
                               &cbRead)) {
            _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
            print_winerr(_T("ReadProcessMemory(CommandLine->Buffer)"));
            CloseHandle(hProcess);
            continue;
        }
        assert(cbRead == ustrTargetCommandLine.Length);
        assert(cbRead < sizeof(wszCmdLine));
        wszCmdLine[ustrTargetCommandLine.Length / 2] = 0;
        _tprintf(_T("PID %lu[%s]: %" PRIsW "\n"), pe32.th32ProcessID, pe32.szExeFile, wszCmdLine);

        /* Spawn a thread inside the process to get the command line through APIs */
        hThread = CreateRemoteThread(hProcess, NULL, 0, lpfctGetCmdLine, NULL, 0, NULL);
        if (!hThread) {
            _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
            print_winerr(_T("CreateRemoteThread"));
            CloseHandle(hProcess);
            continue;
        }
        /* Detect suspended processes by waiting 1 second for the thread */
        dwStatus = WaitForSingleObject(hThread, 1000);
        if (dwStatus == WAIT_FAILED) {
            _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
            print_winerr(_T("WaitForSingleObject(remote thread)"));
            return 1;
        }
        if (dwStatus == WAIT_TIMEOUT) {
            if (!TerminateThread(hThread, 0)) {
                _ftprintf(stderr, _T("PID %lu (%s): "), pe32.th32ProcessID, pe32.szExeFile);
                print_winerr(_T("TerminateThread(remote suspended thread)"));
                /* Fail now */
                return 1;
            }
            CloseHandle(hThread);
            _tprintf(_T("... process is suspended\n"));
        } else if (dwStatus == WAIT_OBJECT_0) {
            /* The thread terminated nicely and its exit code is the result of GetCommandLineW() */
            GetExitCodeThread(hThread, &dwRetAddr);
            CloseHandle(hThread);

            pwszTargetCommandLine = (UINT_PTR)ustrTargetCommandLine.Buffer;
            if (dwRetAddr != 0 && dwRetAddr != (pwszTargetCommandLine & 0xffffffff)) {

                _ftprintf(stderr, _T("PID %lu (%s): Mismatching command line ptr: %#lx != LODWORD(%#" PRIxPTR ")\n"),
                          pe32.th32ProcessID, pe32.szExeFile,
                          dwRetAddr, pwszTargetCommandLine);
                return 1;
            }
        } else {
            _ftprintf(stderr, _T("PID %lu (%s): Unexpected WaitForSingleObject result: %#lx\n"),
                      pe32.th32ProcessID, pe32.szExeFile, dwStatus);
            return 1;
        }

        CloseHandle(hProcess);
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return 0;
}
