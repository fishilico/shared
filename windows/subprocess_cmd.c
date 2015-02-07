/**
 * Spawn cmd.exe as a subprocess and send commands through a pipe
 */
#include "common.h"

/**
 * Read and print available data from the file, in a separate thread
 *
 * This is needed because anonymous pipes do not support async I/O:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365141%28v=vs.85%29.aspx
 * (Anonymous Pipe Operations)
 */
static DWORD WINAPI read_and_print_thread(LPVOID lpParam)
{
    DWORD dwRead, dwWritten;
    BYTE pbBuffer[4096], *pbBuf;
    HANDLE hPipe = (HANDLE)lpParam;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    for (;;) {
        if (!ReadFile(hPipe, pbBuffer, sizeof(pbBuffer), &dwRead, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                /* End here if the other end of the has been closed */
                break;
            }
            print_winerr(_T("ReadFile(pipe)"));
            return 1;
        }
        if (!dwRead) {
            break;
        }
        pbBuf = pbBuffer;
        do {
            dwWritten = 0;
            if (!WriteFile(hStdOut, pbBuf, dwRead, &dwWritten, NULL)) {
                print_winerr(_T("WriteFile(stdout)"));
                return 1;
            }
            assert(dwWritten > 0 && dwWritten <= dwRead);
            dwRead -= dwWritten;
            pbBuf += dwWritten;
        } while (dwRead > 0);
    }
    return 0;
}

/**
 * Write a given text to the file
 */
static BOOL write_text(HANDLE hFile, LPCSTR szText)
{
    DWORD dwSize = strlen(szText);
    DWORD dwWritten = 0;

    do {
        if (!WriteFile(hFile, szText, dwSize, &dwWritten, NULL)) {
            print_winerr(_T("WriteFile"));
            return FALSE;
        }
        assert(dwWritten > 0 && dwWritten <= dwSize);
        dwSize -= dwWritten;
        szText += dwWritten;
    } while (dwSize > 0);
    return TRUE;
}

int _tmain(void)
{
    HANDLE hPipeWrIn = NULL, hPipeRdIn = NULL, hPipeWrOut = NULL, hPipeRdOut = NULL;
    HANDLE hThread;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR szCmdLine[] = { _T('c'), _T('m'), _T('d'), _T('\0') };
    DWORD dwExitCode = 0;
    int ret = 0;

    /* Open partially-inheritable pipes */
    ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hPipeRdIn, &hPipeWrIn, &sa, 0)) {
        print_winerr(_T("CreatePipe(in)"));
        return 1;
    }
    if (!SetHandleInformation(hPipeWrIn, HANDLE_FLAG_INHERIT, 0)) {
        print_winerr(_T("SetHandleInformation(wr-in)"));
        CloseHandle(hPipeRdIn);
        CloseHandle(hPipeWrIn);
        return 1;
    }
    if (!CreatePipe(&hPipeRdOut, &hPipeWrOut, &sa, 0)) {
        print_winerr(_T("CreatePipe(out)"));
        CloseHandle(hPipeRdIn);
        CloseHandle(hPipeWrIn);
        return 1;
    }
    if (!SetHandleInformation(hPipeRdOut, HANDLE_FLAG_INHERIT, 0)) {
        print_winerr(_T("SetHandleInformation(rd-out)"));
        CloseHandle(hPipeRdIn);
        CloseHandle(hPipeWrIn);
        CloseHandle(hPipeRdOut);
        CloseHandle(hPipeWrOut);
        return 1;
    }

    /* Spawn cmd.exe */
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hPipeRdIn;
    si.hStdOutput = hPipeWrOut;
    si.hStdError = hPipeWrOut;

    if (!CreateProcess(NULL, szCmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        print_winerr(_T("CreateProcess(cmd)"));
        CloseHandle(hPipeRdIn);
        CloseHandle(hPipeWrIn);
        CloseHandle(hPipeRdOut);
        CloseHandle(hPipeWrOut);
        return 1;
    }
    CloseHandle(hPipeRdIn);
    CloseHandle(hPipeWrOut);

    /* Start the thread which will consume the output */
    hThread = CreateThread(NULL, 0, read_and_print_thread, (LPVOID)hPipeRdOut, 0, NULL);
    if (hThread == NULL) {
        print_winerr(_T("CreateThread"));
        CloseHandle(hPipeWrIn);
        CloseHandle(hPipeRdOut);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    /* Send some commands with ugly sleeps becase cmd drop commands sent too fast */
    if (!write_text(hPipeWrIn, "echo off\n")) {
        ret = 1;
    }
    if (!ret) {
        Sleep(100);
        if (!write_text(hPipeWrIn, "echo Variables for %COMPUTERNAME%\\%USERNAME%:\n")) {
            ret = 1;
        }
    }
    if (!ret) {
        Sleep(100);
        /* Show %PATH% */
        if (!write_text(hPipeWrIn, "path\n")) {
            ret = 1;
        }
    }
    if (!ret) {
        Sleep(100);
        /* Expected: "OS=Windows_NT" */
        if (!write_text(hPipeWrIn, "echo OS=%OS%\n")) {
            ret = 1;
        }
    }
    if (!ret) {
        Sleep(100);
        /* Expected: "SYSTEMROOT=C:\windows" */
        if (!write_text(hPipeWrIn, "echo SYSTEMROOT=%SYSTEMROOT%\n")) {
            ret = 1;
        }
    }
    if (!ret) {
        Sleep(100);
        /* Expected: "TEMP=C:\users\%USERNAME%\Temp" */
        if (!write_text(hPipeWrIn, "echo TEMP=%TEMP%\n")) {
            ret = 1;
        }
    }
    if (!ret) {
        Sleep(100);
        /* Show Windows version */
        if (!write_text(hPipeWrIn, "ver\n")) {
            ret = 1;
        }
    }
    /* Exit with a specific error code which will be retrieved and checked */
    if (!ret) {
        Sleep(100);
        if (!write_text(hPipeWrIn, "exit 42\n")) {
            ret = 1;
        }
    }
    CloseHandle(hPipeWrIn);

    /* Wait for the consumer thread to end */
    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
        print_winerr(_T("WaitForSingleObject(thread)"));
        ret = 1;
    }
    CloseHandle(hThread);

    /* Close the output pipe and wait for cmd to terminate */
    CloseHandle(hPipeRdOut);
    if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_FAILED) {
        print_winerr(_T("WaitForSingleObject(process)"));
        ret = 1;
    }
    if (!ret && !GetExitCodeProcess(pi.hProcess, &dwExitCode)) {
        print_winerr(_T("GetExitCodeProcess"));
        ret = 1;
    }
    if (!ret && dwExitCode) {
        if (dwExitCode == STILL_ACTIVE) {
            _ftprintf(stderr, _T("Error: subprocess is still alive!\n"));
            ret = 1;
        } else if (dwExitCode != 42) {
            _ftprintf(stderr, _T("Error: unexpected exit code %lu\n"), dwExitCode);
            ret = 1;
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return ret;
}
