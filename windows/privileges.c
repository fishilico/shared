/**
 * Dump process token information (user, groups, privileges...) and enable SeDebugPrivilege
 *
 * From a command line console, it is possible to enumerate the privileges of the current user with:
 *    whoami /priv
 *
 * Privileges can also be dumped from a PowerShell script such as:
 * https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-TokenPrivs.ps1
 */
#include "common.h"
#include <inttypes.h>
#include <ntsecapi.h>
#include <sddl.h>

/* Wrap GetTokenInformation to allocate memory */
_ParamBufSizeToAlloc2(GetTokenInformation,
    HANDLE, TokenHandle, TOKEN_INFORMATION_CLASS, TokenInformationClass)

/* Wrap LookupPrivilegeName to allocate memory */
_ParamStringBufInOutSizeToAlloc2(LookupPrivilegeName, LPCTSTR, lpSystemName, PLUID, lpLuid)

static void DumpProccessToken(VOID)
{
    HANDLE hToken;
    DWORD i, dwAttr, dwRetLen;
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

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {
        print_winerr(_T("OpenProcessToken"));
        return;
    }
    _tprintf(_T("Tokens of current process:\n"));

    dwRetLen = 0;
    pTokenUser = (PTOKEN_USER)GetTokenInformation_a(hToken, TokenUser, &dwRetLen);
    if (pTokenUser) {
        assert(pTokenUser->User.Sid);
        if (!ConvertSidToStringSid(pTokenUser->User.Sid, &szSid)) {
            print_winerr(_T("ConvertSidToStringSid"));
        } else {
            _tprintf(_T("- User: %s"), szSid);
            if (pTokenUser->User.Attributes) {
                _tprintf(_T(" attr 0x%lx"), pTokenUser->User.Attributes);
            }
            _tprintf(_T("\n"));
            LocalFree(szSid);
            szSid = NULL;
        }
        HeapFree(GetProcessHeap(), 0, pTokenUser);
    }

    dwRetLen = 0;
    pTokenGroups = (PTOKEN_GROUPS)GetTokenInformation_a(hToken, TokenGroups, &dwRetLen);
    if (pTokenGroups) {
        _tprintf(_T("- Groups (%ld):\n"), pTokenGroups->GroupCount);
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

    dwRetLen = 0;
    pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInformation_a(hToken, TokenPrivileges, &dwRetLen);
    if (pTokenPrivileges) {
        _tprintf(_T("- Privileges (%ld):\n"), pTokenPrivileges->PrivilegeCount);
        for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
            dwRetLen = 0;
            szPriv = LookupPrivilegeName_a(NULL, &pTokenPrivileges->Privileges[i].Luid, &dwRetLen);
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

    dwRetLen = 0;
    pTokenOwner = (PTOKEN_OWNER)GetTokenInformation_a(hToken, TokenOwner, &dwRetLen);
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

    dwRetLen = 0;
    pTokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP)GetTokenInformation_a(hToken, TokenPrimaryGroup, &dwRetLen);
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

    dwRetLen = 0;
    pTokenSource = (PTOKEN_SOURCE)GetTokenInformation_a(hToken, TokenSource, &dwRetLen);
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
        _tprintf(_T("- Source: \"%s\" {%08lx-%08lx}\n"), szTokenSourceName,
                 pLuid->LowPart, pLuid->HighPart);
        HeapFree(GetProcessHeap(), 0, pTokenSource);
    }

    dwRetLen = 0;
    pTokenType = (PTOKEN_TYPE)GetTokenInformation_a(hToken, TokenType, &dwRetLen);
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
    dwRetLen = 0;
    pTokenElevation = (PTOKEN_ELEVATION)GetTokenInformation_a(hToken, TokenElevation, &dwRetLen);
    if (pTokenElevation) {
        _tprintf(_T("- Elevation: %d\n"), *pTokenElevation);
        HeapFree(GetProcessHeap(), 0, pTokenElevation);
    }

    dwRetLen = 0;
    pTokenElevationType = (PTOKEN_ELEVATION_TYPE)GetTokenInformation_a(hToken, TokenElevationType, &dwRetLen);
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
    TOKEN_PRIVILEGES tpTokenPrivileges;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        print_winerr(_T("LookupPrivilegeValue(SeDebugPrivilege)"));
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        print_winerr(_T("OpenProcessToken"));
        return FALSE;
    }

    ZeroMemory(&tpTokenPrivileges, sizeof(TOKEN_PRIVILEGES));
    tpTokenPrivileges.PrivilegeCount = 1;
    tpTokenPrivileges.Privileges[0].Luid = luid;
    tpTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tpTokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        print_winerr(_T("AdjustTokenPrivileges(Debug)"));
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

/**
 * Enumerate the users through LSA API (Local Security Authority)
 */
static void EnumerateLsaUsers(VOID)
{
    WCHAR wszSystemName[] = L"";
    LSA_UNICODE_STRING lusSystemName, *plusUserRights = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE lsahPolicyHandle = NULL;
    LSA_ENUMERATION_INFORMATION *pLsaEnumInfo = NULL;
    LSA_REFERENCED_DOMAIN_LIST *pLsaReferencedDomains;
    LSA_TRANSLATED_NAME *pLsaName;
    NTSTATUS ntsResult;
    ULONG ulWinError, ulCount = 0, ulIndex, ulCountOfRights, index;
    LPTSTR szSid = NULL;

    lusSystemName.Buffer = wszSystemName;
    lusSystemName.Length = wcslen(wszSystemName) * sizeof(WCHAR);
    lusSystemName.MaximumLength = lusSystemName.Length + sizeof(WCHAR);
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    ntsResult = LsaOpenPolicy(
        &lusSystemName,
        &ObjectAttributes,
        POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION,
        &lsahPolicyHandle);
    if (ntsResult != 0) {
        ulWinError = LsaNtStatusToWinError(ntsResult);
        _tprintf(_T("LsaOpenPolicy returned error %#lx = %#lx\n"), ntsResult, ulWinError);
        SetLastError(ulWinError);
        print_winerr(_T("LsaOpenPolicy"));
        return;
    }

    ntsResult = LsaEnumerateAccountsWithUserRight(
        lsahPolicyHandle, NULL, (VOID **)&pLsaEnumInfo, &ulCount);
    if (ntsResult != 0) {
        ulWinError = LsaNtStatusToWinError(ntsResult);
        _tprintf(_T("LsaEnumerateAccountsWithUserRight returned error %#lx = %#lx\n"),
                 ntsResult, ulWinError);
        SetLastError(ulWinError);
        print_winerr(_T("LsaEnumerateAccountsWithUserRight"));
        goto cleanup;
    }
    _tprintf(_T("LSA handle %#" PRIxPTR ", got %lu accounts at %p\n"),
             (UINT_PTR)lsahPolicyHandle, ulCount, pLsaEnumInfo);
    for (ulIndex = 0; ulIndex < ulCount; ulIndex++) {
        if (!ConvertSidToStringSid(pLsaEnumInfo[ulIndex].Sid, &szSid)) {
            print_winerr(_T("ConvertSidToStringSid"));
            szSid = NULL;
        }

        ulCountOfRights = 0;
        ntsResult = LsaEnumerateAccountRights(
            lsahPolicyHandle, pLsaEnumInfo[ulIndex].Sid, &plusUserRights, &ulCountOfRights);
        if (ntsResult != 0) {
            ulWinError = LsaNtStatusToWinError(ntsResult);
            _tprintf(_T("LsaEnumerateAccountRights returned error %#lx = %#lx\n"), ntsResult, ulWinError);
            SetLastError(ulWinError);
            print_winerr(_T("LsaEnumerateAccountRights"));
            plusUserRights = NULL;
        }
        _tprintf(_T("- Account %s (%lu %s):\n"), szSid, ulCountOfRights,
                 (ulCountOfRights >= 2) ? _T("rights") : _T("right"));

        /* Lookup the name of the user from the given SID */
        pLsaReferencedDomains = NULL;
        pLsaName = NULL;
        ntsResult = LsaLookupSids(
            lsahPolicyHandle, 1, &pLsaEnumInfo[ulIndex].Sid,
            &pLsaReferencedDomains, &pLsaName);
        if (ntsResult != 0) {
            ulWinError = LsaNtStatusToWinError(ntsResult);
            _tprintf(_T("LsaLookupSids returned error %#lx = %#lx\n"), ntsResult, ulWinError);
            SetLastError(ulWinError);
            print_winerr(_T("LsaLookupSids"));
        } else if (pLsaName) {
            _tprintf(_T("  - Name: "));
            if (pLsaName->DomainIndex >= 0) {
                index = pLsaName->DomainIndex;
                /* Note: there is also a Sid field, which is not displayed */
                _tprintf(_T("%.*" PRIsW "\\"),
                         (int)pLsaReferencedDomains->Domains[index].Name.Length / 2,
                         pLsaReferencedDomains->Domains[index].Name.Buffer);
            }
            _tprintf(_T("%.*" PRIsW " ("), (int)pLsaName->Name.Length / 2, pLsaName->Name.Buffer);
            switch ((int)pLsaName->Use) { /* Cast to integer in ordre to prevent warnings about enum */
                case SidTypeUser: /* 1 */
                    _tprintf(_T("user"));
                    break;
                case SidTypeGroup:
                    _tprintf(_T("group"));
                    break;
                case SidTypeDomain:
                    _tprintf(_T("domain"));
                    break;
                case SidTypeAlias:
                    _tprintf(_T("alias"));
                    break;
                case SidTypeWellKnownGroup:
                    _tprintf(_T("well-known group"));
                    break;
                case SidTypeDeletedAccount:
                    _tprintf(_T("deleted account"));
                    break;
                case SidTypeInvalid:
                    _tprintf(_T("invalid"));
                    break;
                case SidTypeUnknown:
                    _tprintf(_T("unknown type"));
                    break;
                case SidTypeComputer:
                    _tprintf(_T("computer"));
                    break;
                case 10 /* SidTypeLabel */:
                    _tprintf(_T("mandatory integrity label"));
                    break;
                case 11 /* SidTypeLogonSession */:
                    _tprintf(_T("logon session"));
                    break;
                default:
                    _tprintf(_T("Unknown use %d"), pLsaName->Use);
            }
            _tprintf(_T(")\n"));
        }

        /* Enumerate the rights */
        if (plusUserRights) {
            for (index = 0; index < ulCountOfRights; index++) {
                _tprintf(
                    _T("  * %.*" PRIsW "\n"),
                    (int)plusUserRights[index].Length / 2,
                    plusUserRights[index].Buffer);
            }
        } else {
            _tprintf(_T("    (no user right)\n"));
        }

        if (pLsaReferencedDomains) {
            LsaFreeMemory(pLsaReferencedDomains);
            pLsaReferencedDomains = NULL;
        }
        if (pLsaName) {
            LsaFreeMemory(pLsaName);
            pLsaName = NULL;
        }
        if (plusUserRights) {
            LsaFreeMemory(plusUserRights);
            plusUserRights = NULL;
        }
        if (szSid) {
            LocalFree(szSid);
            szSid = NULL;
        }
    }

cleanup:
    if (pLsaEnumInfo)
        LsaFreeMemory(pLsaEnumInfo);
    LsaClose(lsahPolicyHandle);
}

int _tmain(void)
{
    DumpProccessToken();
    if (EnableDebugPrivilege()) {
        _tprintf(_T("Successfully enabled SeDebugPrivilege\n"));
    }
    _tprintf(_T("\n"));
    EnumerateLsaUsers();
    return 0;
}
