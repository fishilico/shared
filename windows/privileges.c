/**
 * Dump process token information (user, groups, privileges...) and enable SeDebugPrivilege
 */
#include "common.h"
#include <sddl.h>

/* Wrap GetTokenInformation to allocate memory */
_ParamBufSizeToAlloc2(GetTokenInformation,
    HANDLE, TokenHandle, TOKEN_INFORMATION_CLASS, TokenInformationClass)

/* Wrap LookupPrivilegeName to allocate memory */
_ParamStringBufInOutSizeToAlloc2(LookupPrivilegeName, LPCTSTR, lpSystemName, PLUID, lpLuid)

static void DumpProccessToken(VOID)
{
    HANDLE hToken;
    DWORD i, dwAttr;
    TOKEN_USER *pTokenUser;
    TOKEN_GROUPS *pTokenGroups;
    TOKEN_PRIVILEGES *pTokenPrivileges;
    TOKEN_OWNER *pTokenOwner;
    TOKEN_PRIMARY_GROUP *pTokenPrimaryGroup;
    TOKEN_SOURCE *pTokenSource;
    TOKEN_TYPE *pTokenType;
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
    TOKEN_ELEVATION *pTokenElevation;
    TOKEN_ELEVATION_TYPE *pTokenElevationType;
#endif
    LPTSTR szSid = NULL, szPriv = NULL;
    TCHAR szTokenSourceName[TOKEN_SOURCE_LENGTH + 1];
    const LUID *pLuid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        print_winerr(_T("OpenProcessToken"));
        return;
    }
    _tprintf(_T("Tokens of current process:\n"));

    pTokenUser = (PTOKEN_USER)GetTokenInformation_a(hToken, TokenUser, NULL);
    if (pTokenUser) {
        assert(pTokenUser->User.Sid);
        if (!ConvertSidToStringSid(pTokenUser->User.Sid, &szSid)) {
            print_winerr(_T("ConvertSidToStringSid"));
        } else {
            _tprintf(_T("- User: %s"), szSid);
            if (pTokenUser->User.Attributes) {
                _tprintf(_T(" attr 0x%x"), pTokenUser->User.Attributes);
            }
            _tprintf(_T("\n"));
            LocalFree(szSid);
            szSid = NULL;
        }
        HeapFree(GetProcessHeap(), 0, pTokenUser);
    }

    pTokenGroups = (PTOKEN_GROUPS)GetTokenInformation_a(hToken, TokenGroups, NULL);
    if (pTokenGroups) {
        _tprintf(_T("- Groups (%d):\n"), pTokenGroups->GroupCount);
        for (i = 0; i < pTokenGroups->GroupCount; i++) {
            if (!ConvertSidToStringSid(pTokenGroups->Groups[i].Sid, &szSid)) {
                print_winerr(_T("ConvertSidToStringSid"));
                continue;
            }
            _tprintf(_T("   * %s ("), szSid);
            dwAttr = pTokenGroups->Groups[i].Attributes;
            if (dwAttr & SE_GROUP_USE_FOR_DENY_ONLY) {
                _tprintf(_T("deny-only"));
            } else if (!(dwAttr & SE_GROUP_ENABLED)) {
                _tprintf(_T("disabled"));
            } else if ((dwAttr & SE_GROUP_ENABLED_BY_DEFAULT) && (dwAttr & SE_GROUP_MANDATORY)) {
                _tprintf(_T("enabled"));
            } else {
                _tprintf(_T("enabled,non-mandatory"));
            }

            if (dwAttr & SE_GROUP_INTEGRITY) {
                _tprintf(_T(", integrity SID"));
            }
            if (dwAttr & SE_GROUP_INTEGRITY_ENABLED) {
                _tprintf(_T(", enabled for integrity checks"));
            }
            if ((dwAttr & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
                _tprintf(_T(", logon SID"));
            }
            if (dwAttr & SE_GROUP_OWNER) {
                _tprintf(_T(", owner"));
            }
            if (dwAttr & SE_GROUP_RESOURCE) {
                _tprintf(_T(", domain-local group"));
            }
            _tprintf(_T(")\n"));
            LocalFree(szSid);
            szSid = NULL;
        }
        HeapFree(GetProcessHeap(), 0, pTokenGroups);
    }

    pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInformation_a(hToken, TokenPrivileges, NULL);
    if (pTokenPrivileges) {
        _tprintf(_T("- Privileges (%d):\n"), pTokenPrivileges->PrivilegeCount);
        for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
            szPriv = LookupPrivilegeName_a(NULL, &pTokenPrivileges->Privileges[i].Luid, NULL);
            if (!szPriv) {
                pLuid = &pTokenPrivileges->Privileges[i].Luid;
                szPriv = HeapAlloc(GetProcessHeap(), 0, 20 * sizeof(TCHAR));
                if (!szPriv) {
                    print_winerr(_T("HeapAlloc"));
                    continue;
                }
                _sntprintf(szPriv, 20, _T("{%08x-%08lx}"), pLuid->LowPart, pLuid->HighPart);
            }
            dwAttr = pTokenPrivileges->Privileges[i].Attributes;
            _tprintf(_T("   %c %s ("), (dwAttr & SE_PRIVILEGE_ENABLED) ? '+' : '-', szPriv);
            if (dwAttr & SE_PRIVILEGE_ENABLED) {
                if (dwAttr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
                    _tprintf(_T("enabled"));
                } else {
                    _tprintf(_T("explicitly enabled"));
                }
            } else {
                if (dwAttr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
                    _tprintf(_T("explicitly disabled"));
                } else {
                    _tprintf(_T("disabled"));
                }
            }
            if (dwAttr & SE_PRIVILEGE_USED_FOR_ACCESS) {
                _tprintf(_T(", used for access"));
            }
            _tprintf(_T(")\n"));
            HeapFree(GetProcessHeap(), 0, szPriv);
        }
        HeapFree(GetProcessHeap(), 0, pTokenPrivileges);
    }

    pTokenOwner = (PTOKEN_OWNER)GetTokenInformation_a(hToken, TokenOwner, NULL);
    if (pTokenOwner) {
        assert(pTokenOwner->Owner);
        if (!ConvertSidToStringSid(pTokenOwner->Owner, &szSid)) {
            print_winerr(_T("ConvertSidToStringSid"));
        } else {
            _tprintf(_T("- Owner (new objects): %s\n"), szSid);
            LocalFree(szSid);
            szSid = NULL;
        }
        HeapFree(GetProcessHeap(), 0, pTokenOwner);
    }

    pTokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP)GetTokenInformation_a(hToken, TokenPrimaryGroup, NULL);
    if (pTokenPrimaryGroup) {
        assert(pTokenPrimaryGroup->PrimaryGroup);
        if (!ConvertSidToStringSid(pTokenPrimaryGroup->PrimaryGroup, &szSid)) {
            print_winerr(_T("ConvertSidToStringSid"));
        } else {
            _tprintf(_T("- Primary Group: %s\n"), szSid);
            LocalFree(szSid);
            szSid = NULL;
        }
        HeapFree(GetProcessHeap(), 0, pTokenPrimaryGroup);
    }

    pTokenSource = (PTOKEN_SOURCE)GetTokenInformation_a(hToken, TokenSource, NULL);
    if (pTokenSource) {
#if defined(UNICODE)
        if (!MultiByteToWideChar(CP_ACP, 0,
                                 pTokenSource->SourceName, TOKEN_SOURCE_LENGTH,
                                 szTokenSourceName, TOKEN_SOURCE_LENGTH)) {
            print_winerr(_T("MultiByteToWideChar"));
            _sntprintf(szTokenSourceName, TOKEN_SOURCE_LENGTH + 1, _T("(error)"));
        }
#else
        CopyMemory(szTokenSourceName, pTokenSource->SourceName, TOKEN_SOURCE_LENGTH);
#endif
        szTokenSourceName[TOKEN_SOURCE_LENGTH] = 0;
        pLuid = &pTokenSource->SourceIdentifier;
        _tprintf(_T("- Source: %s {%08x-%08lx}\n"), szTokenSourceName,
                 pLuid->LowPart, pLuid->HighPart);
        HeapFree(GetProcessHeap(), 0, pTokenSource);
    }

    pTokenType = (PTOKEN_TYPE)GetTokenInformation_a(hToken, TokenType, NULL);
    if (pTokenType) {
        _tprintf(_T("- Type: "));
        switch (*pTokenType) {
            case TokenPrimary:
                _tprintf(_T("primary token"));
                break;
            case TokenImpersonation:
                _tprintf(_T("impersonation token"));
                break;
            default:
                _tprintf(_T("unknown type %d"), *pTokenType);
        }
        _tprintf(_T("\n"));
        HeapFree(GetProcessHeap(), 0, pTokenType);
    }

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
    pTokenElevation = (PTOKEN_ELEVATION)GetTokenInformation_a(hToken, TokenElevation, NULL);
    if (pTokenElevation) {
        _tprintf(_T("- Elevation: %d\n"), *pTokenElevation);
        HeapFree(GetProcessHeap(), 0, pTokenElevation);
    }

    pTokenElevationType = (PTOKEN_ELEVATION_TYPE)GetTokenInformation_a(hToken, TokenElevationType, NULL);
    if (pTokenElevationType) {
        _tprintf(_T("- Elevation type: "));
        switch (*pTokenElevationType) {
            case TokenElevationTypeDefault:
                _tprintf(_T("default"));
                break;
            case TokenElevationTypeFull:
                _tprintf(_T("full"));
                break;
            case TokenElevationTypeLimited:
                _tprintf(_T("limited"));
                break;
            default:
                _tprintf(_T("unknown type %d"), *pTokenElevationType);
        }
        _tprintf(_T("\n"));
        HeapFree(GetProcessHeap(), 0, pTokenElevationType);
    }
#endif /* Vista */

    CloseHandle(hToken);
}

static BOOL EnableDebugPrivilege(VOID)
{
    LUID luid;
    HANDLE hToken;
    TOKEN_PRIVILEGES TokenPrivileges;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        print_winerr(_T("LookupPrivilegeValue(SeDebugPrivilege)"));
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        print_winerr(_T("OpenProcessToken"));
        return FALSE;
    }

    ZeroMemory(&TokenPrivileges, sizeof(TOKEN_PRIVILEGES));
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid = luid;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        print_winerr(_T("AdjustTokenPrivileges(Debug)"));
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

int _tmain()
{
    DumpProccessToken();
    if (EnableDebugPrivilege()) {
        _tprintf(_T("Successfully enabled SeDebugPrivilege\n"));
    }
    return 0;
}
