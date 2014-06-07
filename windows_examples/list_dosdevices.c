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
static BOOL QueryDosDeviceWithAlloc(LPCTSTR lpDeviceName, LPTSTR *lppTargetPath, DWORD *pccSize){
    LPTSTR buffer = NULL;
    DWORD ccSize = 1024, ccRet;

    assert(lppTargetPath && pccSize);
    do {
        buffer = HeapAlloc(GetProcessHeap(), 0, ccSize * sizeof(TCHAR));
        if (!buffer) {
            print_winerr(_T("HeapAlloc"));
            return FALSE;
        }
        ccRet = QueryDosDevice(lpDeviceName, buffer, ccSize);
        if (ccRet) {
            assert(ccRet <= ccSize);
        } else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            ccSize *= 2;
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        } else {
            print_winerr(_T("QueryDosDevice"));
            HeapFree(GetProcessHeap(), 0, buffer);
            return FALSE;
        }
    } while (!ccRet);
    *pccSize = ccRet;
    *lppTargetPath = buffer;
    return TRUE;
}

static int CompareStringList(const void *arg1, const void *arg2)
{
    return _tcsicmp(*(const LPCTSTR*)arg1, *(const LPCTSTR*)arg2);
}

int _tmain()
{
    LPTSTR lszDosDevicesList, szDosDevice, lszDevicePathsList;
    LPTSTR *aszDosDevices;
    DWORD ccSize, nDevices, i;

    if (!QueryDosDeviceWithAlloc(NULL, &lszDosDevicesList, &ccSize)) {
        return 1;
    }

    /* Sort the DosDevices list using an array of strings */
    for (szDosDevice = lszDosDevicesList, i = 0; *szDosDevice; i++) {
        size_t len = _tcslen(szDosDevice);
        szDosDevice = _tcsninc(szDosDevice, len + 1);
        assert((size_t)(szDosDevice - lszDosDevicesList) < ccSize);
    }
    nDevices = i;
    aszDosDevices = HeapAlloc(GetProcessHeap(), 0, nDevices * sizeof(LPTSTR));
    if (!aszDosDevices) {
        print_winerr(_T("HeapAlloc"));
        return 1;
    }
    for (szDosDevice = lszDosDevicesList, i = 0; *szDosDevice; i++) {
        size_t len;
        aszDosDevices[i] = szDosDevice;
        len = _tcslen(szDosDevice);
        szDosDevice = _tcsninc(szDosDevice, len + 1);
        assert((size_t)(szDosDevice - lszDosDevicesList) < ccSize);
    }
    qsort(aszDosDevices, nDevices, sizeof(LPTSTR), CompareStringList);

    for (i = 0; i < nDevices; i ++) {
        LPTSTR szPath;
        _tprintf(_T("%s"), aszDosDevices[i]);
        if (!QueryDosDeviceWithAlloc(aszDosDevices[i], &lszDevicePathsList, &ccSize)) {
            break;
        }
        for (szPath = lszDevicePathsList; *szPath;) {
            size_t len;
            _tprintf(_T(" -> %s "), szPath);
            len = _tcslen(szPath);
            szPath = _tcsninc(szPath, len + 1);
            assert((size_t)(szPath - lszDevicePathsList) < ccSize);
        }
        printf("\n");
        HeapFree(GetProcessHeap(), 0, lszDevicePathsList);
    }
    HeapFree(GetProcessHeap(), 0, aszDosDevices);
    HeapFree(GetProcessHeap(), 0, lszDosDevicesList);
    return 0;
}
