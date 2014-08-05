/**
 * List logical drives and volumes with some meta-information
 */
#define _WIN32_WINNT 0x0500 /* Needed for FindFirstVolume... in winbase.h */
#include "common.h"

#if (_WIN32_WINNT >= 0x0501)
/* Wrap GetVolumePathNamesForVolumeName to allocate memory */
_ParamStringBufSizeToAlloc1(GetVolumePathNamesForVolumeName, LPCTSTR, lpszVolumeName);
#endif

static LPCTSTR DescribeDriveType(UINT type)
{
    switch(type) {
        case DRIVE_UNKNOWN:
            return _T("Unknown");
        case DRIVE_NO_ROOT_DIR:
            return _T("No root dir");
        case DRIVE_REMOVABLE:
            return _T("Removable");
        case DRIVE_FIXED:
            return _T("Fixed");
        case DRIVE_REMOTE:
            return _T("Remote");
        case DRIVE_CDROM:
            return _T("CD-ROM");
        case DRIVE_RAMDISK:
            return _T("Ram disk");
    }
    return NULL;
}

static BOOL enum_logical_drives(void)
{
    BOOL bSuccess;
    DWORD dwLogicalDrives, i;
    TCHAR szRootPathName[4] = _T("?:\\");
    UINT type;
    LPCTSTR szType;
    TCHAR szVolumeMountPoint[MAX_PATH] = _T("");
    TCHAR szVolumeName[MAX_PATH] = _T("");
    DWORD dwVolumeSerialNumber, dwMaximumComponentLength, dwFileSystemFlags;
    TCHAR szFileSystemNameBuffer[MAX_PATH] = _T("");

    /* Enumerate logical drives with GetLogicalDrives */
    dwLogicalDrives = GetLogicalDrives();
    if (!dwLogicalDrives) {
        print_winerr(_T("GetLogicalDrives"));
        return FALSE;
    }

    _tprintf(_T("Logical drives:"));
    for (i = 0; i < 26 && (dwLogicalDrives >> i); i++) {
        if ((dwLogicalDrives >> i) & 1) {
            _tprintf(_T(" %c"), 'A' + i);
        }
    }
    if (dwLogicalDrives >> i) {
         _tprintf(_T(" and x%lx"), dwLogicalDrives >> i);
    }
    _tprintf(_T("\n"));

    for (i = 0; i < 26 && (dwLogicalDrives >> i); i++) {
        if (!((dwLogicalDrives >> i) & 1)) continue;

        szRootPathName[0] = 'A' + i;
        type = GetDriveType(szRootPathName);
        szType = DescribeDriveType(type);
        _tprintf(_T("* %s, "), szRootPathName);
        if (szType) {
            _tprintf(_T("type %s\n"), szType);
        } else {
            _tprintf(_T("unknown type %u\n"), type);
        }

        if (!GetVolumeNameForVolumeMountPoint(szRootPathName, szVolumeMountPoint, ARRAYSIZE(szVolumeMountPoint))) {
            print_winerr(_T("GetVolumeNameForVolumeMountPoint"));
        } else {
            _tprintf(_T("  - Volume Mount Point: %s\n"), szVolumeMountPoint);
        }
        bSuccess = GetVolumeInformation(
            szRootPathName, szVolumeName, ARRAYSIZE(szVolumeName),
            &dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags,
            szFileSystemNameBuffer, ARRAYSIZE(szFileSystemNameBuffer));
        if (!bSuccess) {
            if(GetLastError() == ERROR_NOT_READY) {
                _tprintf(_T("  Not Ready\n"));
            } else {
                print_winerr(_T("GetVolumeInformation"));
            }
        } else {
            _tprintf(_T("  - Volume Name: %s\n"), szVolumeName);
            _tprintf(_T("  - Volume Serial Number: x%08lx\n"), dwVolumeSerialNumber);
            _tprintf(_T("  - Maximum Component Length: %ld\n"), dwMaximumComponentLength);//Taille entre deux slashes
            _tprintf(_T("  - FS Name: %s\n"), szFileSystemNameBuffer);
            _tprintf(_T("  - FS Flags: x%08lx\n"), dwFileSystemFlags);
#define print_flag(mask, name) do { if (dwFileSystemFlags&(mask)) _tprintf(_T("      "#name"\n"));} while (0)
            print_flag(0x00000001, FILE_CASE_SENSITIVE_SEARCH);
            print_flag(0x00000002, FILE_CASE_PRESERVED_NAMES);
            print_flag(0x00000004, FILE_UNICODE_ON_DISK);
            print_flag(0x00000008, FILE_PERSISTENT_ACLS);
            print_flag(0x00000010, FILE_FILE_COMPRESSION);
            print_flag(0x00000020, FILE_VOLUME_QUOTAS);
            print_flag(0x00000040, FILE_SUPPORTS_SPARSE_FILES);
            print_flag(0x00000080, FILE_SUPPORTS_REPARSE_POINTS);

            print_flag(0x00008000, FILE_VOLUME_IS_COMPRESSED);
            print_flag(0x00010000, FILE_SUPPORTS_OBJECT_IDS);
            print_flag(0x00020000, FILE_SUPPORTS_ENCRYPTION);
            print_flag(0x00040000, FILE_NAMED_STREAMS);
            print_flag(0x00080000, FILE_READ_ONLY_VOLUME);
            print_flag(0x00100000, FILE_SEQUENTIAL_WRITE_ONCE);
            print_flag(0x00200000, FILE_SUPPORTS_TRANSACTIONS);
            print_flag(0x00400000, FILE_SUPPORTS_HARD_LINKS);
            print_flag(0x00800000, FILE_SUPPORTS_EXTENDED_ATTRIBUTES);
            print_flag(0x01000000, FILE_SUPPORTS_OPEN_BY_FILE_ID);
            print_flag(0x02000000, FILE_SUPPORTS_USN_JOURNAL); /* USN = Update Sequence Number */
        }
    }
    return TRUE;
}

static BOOL enum_volumes(void)
{
    HANDLE hFindVol, hFindMP;
    TCHAR szVolumeName[MAX_PATH] = _T("");
    TCHAR szVolumeMountPoint[MAX_PATH] = _T("");
    BOOL bSuccess;
    LPTSTR lpszVolumePathNames;
    LPCTSTR szItem;
    DWORD cchLength, err;

    hFindVol = FindFirstVolume(szVolumeName, ARRAYSIZE(szVolumeName));
    if (hFindVol == INVALID_HANDLE_VALUE) {
        print_winerr(_T("FindFirstVolume"));
        return FALSE;
    }
    _tprintf(_T("Volumes:\n"));
    do {
        _tprintf(_T("* %s\n"), szVolumeName);

#if (_WIN32_WINNT >= 0x0501)
        /* Get volume paths */
        lpszVolumePathNames = GetVolumePathNamesForVolumeName_a(szVolumeName, &cchLength);
        if (!lpszVolumePathNames) {
            FindVolumeClose(hFindVol);
            return FALSE;
        }
        foreach_str(szItem, lpszVolumePathNames, cchLength) {
            _tprintf(_T("  - Volume Path Name: %s\n"), szItem);
        }
        HeapFree(GetProcessHeap(), 0, lpszVolumePathNames);
#else
        /* Mark variable as used */
        (void)lpszVolumePathNames;
        (void)szItem;
        (void)cchLength;
#endif

        /* Find mount points */
        hFindMP = FindFirstVolumeMountPoint(szVolumeName, szVolumeMountPoint, ARRAYSIZE(szVolumeMountPoint));
        if (hFindMP == INVALID_HANDLE_VALUE) {
            err = GetLastError();
            if (err != ERROR_NO_MORE_FILES && err != ERROR_CALL_NOT_IMPLEMENTED) {
                print_winerr(_T("FindFirstVolume"));
                FindVolumeClose(hFindVol);
                return FALSE;
            }
        } else {
            do {
                _tprintf(_T("  - Mount Point: %s\n"), szVolumeMountPoint);
                bSuccess = FindNextVolumeMountPoint(hFindMP, szVolumeMountPoint, ARRAYSIZE(szVolumeMountPoint));
                if (!bSuccess && GetLastError() != ERROR_NO_MORE_FILES) {
                    print_winerr(_T("FindNextVolume"));
                    break; /* Non-fatal error */
                }
            } while (bSuccess);
            FindVolumeMountPointClose(hFindMP);
        }

        /* Next volume */
        bSuccess = FindNextVolume(hFindVol, szVolumeName, ARRAYSIZE(szVolumeName));
        if (!bSuccess && GetLastError() != ERROR_NO_MORE_FILES) {
            print_winerr(_T("FindNextVolume"));
            return FALSE;
        }
    } while (bSuccess);
    FindVolumeClose(hFindVol);
    return TRUE;
}

int _tmain()
{
    if (!enum_logical_drives()) return 1;
    _tprintf(_T("\n"));
    if (!enum_volumes()) return 1;
    return 0;
}
