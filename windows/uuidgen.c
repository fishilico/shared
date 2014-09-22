/**
 * Generate an Universal Unique Identifier using Windows API
 *
 * Link with rpcrt4.dll
 */
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

int _tmain()
{
    LPCTSTR szDesc;
    UUID uuid;
    RPC_STATUS stat = UuidCreate(&uuid);
    if (stat == S_OK) {
        szDesc = _T("Global UUID");
    } else if (stat == RPC_S_UUID_LOCAL_ONLY) {
        szDesc = _T("Local UUID");
    } else if (stat == RPC_S_UUID_NO_ADDRESS) {
        szDesc = _T("Local UUID (hardware issue)");
    } else {
        _ftprintf(stderr, _T("UuidCreate: error 0x%08lx\n"), stat);
        return 1;
    }

    _tprintf(_T("%s: {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n"),
             szDesc,
             uuid.Data1, uuid.Data2, uuid.Data3,
             uuid.Data4[0], uuid.Data4[1], uuid.Data4[2], uuid.Data4[3],
             uuid.Data4[4], uuid.Data4[5], uuid.Data4[6], uuid.Data4[7]);
    return 0;
}
