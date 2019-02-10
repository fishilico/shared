/**
 * Watch the changes of a directory.
 *
 * MSDN documentation:
 * * https://docs.microsoft.com/en-gb/windows/desktop/api/winbase/nf-winbase-readdirectorychangesw
 * * https://docs.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher?view=netframework-4.7.2
 */
#include "common.h"

#define NOTIFY_BUFFER_SIZE 64000

static BOOL WatchDirectory(LPTSTR lpszDirectory)
{
    HANDLE hDirectory;
    FILE_NOTIFY_INFORMATION *pNotifyInfo;
    PBYTE pNotifyBuffer;
    BOOL bResult = FALSE;
    DWORD dwBytesReturned, dwOffset;
    LPCTSTR lpszAction;

    pNotifyBuffer = HeapAlloc(GetProcessHeap(), 0, NOTIFY_BUFFER_SIZE);
    if (!pNotifyBuffer) {
        print_winerr(_T("HeapAlloc"));
        return FALSE;
    }
    hDirectory = CreateFile(
        lpszDirectory,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);
    if (hDirectory == INVALID_HANDLE_VALUE) {
        print_winerr(_T("CreateFile(open directory)"));
        goto cleanup;
    }
    _tprintf(_T("Waiting for events for %s\n"), lpszDirectory);
    while (TRUE) {
        dwBytesReturned = 0;
        ZeroMemory(pNotifyBuffer, NOTIFY_BUFFER_SIZE);
        bResult = ReadDirectoryChangesW(
            hDirectory,
            pNotifyBuffer,
            NOTIFY_BUFFER_SIZE,
            TRUE, /* bWatchSubtree */
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            /* FILE_NOTIFY_CHANGE_LAST_ACCESS | */
            FILE_NOTIFY_CHANGE_CREATION |
            FILE_NOTIFY_CHANGE_SECURITY |
            0,
            &dwBytesReturned, NULL, NULL);
        if (!bResult) {
            print_winerr(_T("ReadDirectoryChanges"));
            goto cleanup;
        }
        assert(dwBytesReturned <= NOTIFY_BUFFER_SIZE);
        for (dwOffset = 0; dwOffset < dwBytesReturned; dwOffset += pNotifyInfo->NextEntryOffset) {
            pNotifyInfo = (FILE_NOTIFY_INFORMATION *)&pNotifyBuffer[dwOffset];
            switch (pNotifyInfo->Action) {
                case FILE_ACTION_ADDED:
                    lpszAction = _T("added");
                    break;
                case FILE_ACTION_REMOVED:
                    lpszAction = _T("removed");
                    break;
                case FILE_ACTION_MODIFIED:
                    lpszAction = _T("modified");
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    lpszAction = _T("renamed (old name)");
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    lpszAction = _T("renamed (new name)");
                    break;
#ifdef FILE_ACTION_ADDED_STREAM /* Windows DDK */
                case FILE_ACTION_ADDED_STREAM:
                    lpszAction = _T("added stream");
                    break;
                case FILE_ACTION_REMOVED_STREAM:
                    lpszAction = _T("removed stream");
                    break;
                case FILE_ACTION_MODIFIED_STREAM:
                    lpszAction = _T("modified stream");
                    break;
                case FILE_ACTION_REMOVED_BY_DELETE:
                    lpszAction = _T("removed by delete");
                    break;
                case FILE_ACTION_ID_NOT_TUNNELLED:
                    lpszAction = _T("ID not tunnelled");
                    break;
                case FILE_ACTION_TUNNELLED_ID_COLLISION:
                    lpszAction = _T("tunnelled ID collision");
                    break;
#endif
                default:
                    lpszAction = _T("?");
            }
            _tprintf(_T("Action %lu (%s): %.*" PRIsW "\n"),
                     pNotifyInfo->Action, lpszAction,
                     (int)(pNotifyInfo->FileNameLength / 2),
                     pNotifyInfo->FileName);

            if (!pNotifyInfo->NextEntryOffset)
                break;
        }
    }
    bResult = TRUE;
cleanup:
    if (hDirectory != INVALID_HANDLE_VALUE)
        CloseHandle(hDirectory);
    HeapFree(GetProcessHeap(), 0, pNotifyBuffer);
    return bResult;
}

int _tmain(int argc, TCHAR **argv)
{
    if (argc != 2) {
        _tprintf(_T("Usage: %s DIRECTORY\n"), argv[0]);
        return 1;
    }

    if (!WatchDirectory(argv[1])) {
        return 1;
    }
    return 0;
}
