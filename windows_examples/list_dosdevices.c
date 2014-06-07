/**
 * List the available DOS devices, using QueryDosDevice.
 *
 * Documentation:
 *     DWORD WINAPI QueryDosDevice(
 *         IN LPCTSTR lpDeviceName,  // may be NULL for all entries
 *         OUT LPTSTR lpTargetPath,  // array of nul-terminated strings ended with an empty one
 *         IN DWORD ucchMax);        // character count of lpTargetPath
 */
#include <assert.h>
#include "common.h"

/**
 * Wrap QueryDosDevice to allocate memory
 */
static BOOL QueryDosDeviceWithAlloc(LPCTSTR lpDeviceName, LPTSTR *lppTargetPath, DWORD *pcchSize){
    LPTSTR buffer = NULL;
    DWORD cchSize = 1024, cchRet;

    assert(lppTargetPath && pcchSize);
    do {
        buffer = HeapAlloc(GetProcessHeap(), 0, cchSize * sizeof(TCHAR));
        if (!buffer) {
            print_winerr(_T("HeapAlloc"));
            return FALSE;
        }
        cchRet = QueryDosDevice(lpDeviceName, buffer, cchSize);
        if (cchRet) {
            assert(cchRet <= cchSize);
        } else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            cchSize *= 2;
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        } else {
            print_winerr(_T("QueryDosDevice"));
            HeapFree(GetProcessHeap(), 0, buffer);
            return FALSE;
        }
    } while (!cchRet);
    *pcchSize = cchRet;
    *lppTargetPath = buffer;
    return TRUE;
}

static int CompareStringList(const void *arg1, const void *arg2)
{
    return _tcsicmp(*(const LPCTSTR*)arg1, *(const LPCTSTR*)arg2);
}

int _tmain()
{
    LPTSTR lszDosDevicesList, lszDevicePathsList;
    LPCTSTR szDosDevice, szPath;
    LPCTSTR *aszDosDevices;
    DWORD cchSize, nDevices, i;

    if (!QueryDosDeviceWithAlloc(NULL, &lszDosDevicesList, &cchSize)) {
        return 1;
    }

    /* Sort the Dos Devices list using an array of strings */
    nDevices = 0;
    foreach_str(szDosDevice, lszDosDevicesList, cchSize) {
        nDevices ++;
    }
    aszDosDevices = HeapAlloc(GetProcessHeap(), 0, nDevices * sizeof(LPCTSTR));
    if (!aszDosDevices) {
        print_winerr(_T("HeapAlloc"));
        return 1;
    }
    i = 0;
    foreach_str(szDosDevice, lszDosDevicesList, cchSize) {
        aszDosDevices[i++] = szDosDevice;
    }
    qsort(aszDosDevices, nDevices, sizeof(LPTSTR), CompareStringList);

    /* Print the sorted array */
    for (i = 0; i < nDevices; i ++) {
        _tprintf(_T("%s"), aszDosDevices[i]);
        if (!QueryDosDeviceWithAlloc(aszDosDevices[i], &lszDevicePathsList, &cchSize)) {
            break;
        }
        foreach_str(szPath, lszDevicePathsList, cchSize) {
            _tprintf(_T(" -> %s"), szPath);
        }
        _tprintf(_T("\n"));
        HeapFree(GetProcessHeap(), 0, lszDevicePathsList);
    }
    HeapFree(GetProcessHeap(), 0, aszDosDevices);
    HeapFree(GetProcessHeap(), 0, lszDosDevicesList);
    return 0;
}
