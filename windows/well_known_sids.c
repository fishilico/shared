/**
 * Well-known security identifiers (SIDs) can be built with macros
 *
 * Documentation:
 * * MSDN articles:
 *   * https://msdn.microsoft.com/en-us/library/windows/desktop/aa379597(v=vs.85).aspx "SID Components"
 *   * https://msdn.microsoft.com/en-us/library/windows/desktop/aa379649(v=vs.85).aspx "Well-known SIDs"
 *   * https://msdn.microsoft.com/en-us/library/cc980032.aspx "Well-Known SID Structures"
 *   * https://msdn.microsoft.com/en-us/library/cc237940.aspx "SID Filtering and Claims Transformation"
 *   * https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
 * * CreateWellKnownSid function
 * * Wine: http://source.winehq.org/git/wine.git/blob/HEAD:/dlls/advapi32/security.c
 * * Mimikatz protection with Protected Users group, S-1-5-21-<domain>-525:
 *   https://jimshaver.net/2016/02/14/defending-against-mimikatz/
 * * winnt.h from Windows SDK:
 *   https://www.codemachine.com/downloads/win10rs3/winnt.h
 * * Found SACL "Trust Label ACE: S-1-19-512-4096 (WINDOWS LITE)"
 *   https://github.com/ionescu007/lxss (Black Hat 2016)
 *
 * To regenarate comments in main, use the following command:
 *    well_known_sids.exe > a.txt
 *    sed -n 's,^\(S-[^ =]\+\( [^ =]\+\)*\) *= *\([^\r]*\),s!\\(show_[0-9a-zA-Z_]*sid.*"\3".*;\\).*!\\1 /''* \1 *''/!,p' < a.txt > b.sed
 *    sed -f b.sed -i well_known_sids.c
 */
#include "common.h"
#include <sddl.h>

/**
 * Show the given sid with a description.
 * If a place-holder is given, it replaces the selected parts of the final SID, if there where not zero.
 */
static void _show_sid(
    LPCTSTR szDesc, PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
    BYTE nSubAuthorityCount,
    DWORD dwSA0, DWORD dwSA1, DWORD dwSA2, DWORD dwSA3, DWORD dwSA4,
    DWORD dwSA5, DWORD dwSA6, DWORD dwSA7,
    LPCTSTR placeholder, BYTE placeholder_start, BYTE placeholder_num)
{
    PSID pSid = NULL;
    LPTSTR szSid = NULL, szNewSid;
    SIZE_T srcpos, dstpos;
    if (!AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount,
                                  dwSA0, dwSA1, dwSA2, dwSA3,
                                  dwSA4, dwSA5, dwSA6, dwSA7, &pSid)) {
        print_winerr(_T("AllocateAndInitializeSid"));
        exit(1);
    }
    assert(pSid);
    if (!ConvertSidToStringSid(pSid, &szSid)) {
        print_winerr(_T("ConvertSidToStringSid"));
        FreeSid(pSid);
        exit(1);
    }
    FreeSid(pSid);
    assert(szSid);

    if (placeholder_num && placeholder) {
        /* Allocate a new sid */
        szNewSid = LocalAlloc(LPTR, (_tcslen(szSid) + _tcslen(placeholder) + 3) * sizeof(TCHAR));
        if (!szNewSid) {
            print_winerr(_T("LocalAlloc"));
            LocalFree(szSid);
            exit(1);
        }
        /* Replace in szSid some SID components with a placeholder */
        for (srcpos = 0, dstpos = 0; szSid[srcpos]; srcpos++) {
            if (placeholder_start) {
                /* Before the placeholder: copy */
                szNewSid[dstpos++] = szSid[srcpos];

                /* Count the - */
                if (szSid[srcpos] != _T('-')) {
                    continue;
                }
                placeholder_start--;
                if (placeholder_start == 0) {
                    /* Put the placeholder here while ignore ph_num items */
                    szNewSid[dstpos++] = _T('<');
                    _tcscpy(&szNewSid[dstpos], placeholder);
                    dstpos += _tcslen(placeholder);
                    szNewSid[dstpos++] = _T('>');
                }
            } else if (placeholder_num) {
                /* In the things replaced by the placeholder, skip */
                if (szSid[srcpos] == _T('-')) {
                    placeholder_num--;
                    if (!placeholder_num) {
                        szNewSid[dstpos++] = _T('-');
                    }
                }
            } else {
                /* At the end, copy again */
                szNewSid[dstpos++] = szSid[srcpos];
            }
        }
        /* Sanity checks: check that the placeholder has been replaced */
        assert(placeholder_start == 0);
        assert(placeholder_num == 0);
        szNewSid[dstpos] = 0;
        LocalFree(szSid);
        szSid = szNewSid;
    }

    _tprintf(_T("%-12s = %s\n"), szSid, szDesc);
    LocalFree(szSid);
}

/*
 * As some definitions may happen not to be defined, use preprocessor
 * stringification process to detect undefined constants.
 */
#define _show_sid_ifdef(d, a, n, sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7, ph, phs, phn, name, value) \
    do { \
        if (!strncmp(#value, "SECURITY_", 9) || !strncmp(#value, "DOMAIN_", 7)) { \
            _tprintf(_T("%-12s = %s\n"), _T("??? (undef)"), d); \
        } else { \
            DWORD _dwSa = 0, _base = 10; \
            const char *_v = #value; \
            while (*_v == '(') { \
                _v++; \
            } \
            if (_v[0] == '0' && _v[1] == 'x') { \
                _base = 16; \
                _v += 2; \
            } \
            while (*_v && *_v != ')' && *_v != 'l' && *_v != 'L') { \
                if (*_v >= '0' && *_v <= '9') { \
                    _dwSa = _dwSa * _base + (DWORD)(*_v - '0'); \
                } else if (*_v >= 'a' && *_v <= 'f') { \
                    _dwSa = _dwSa * _base + (DWORD)(*_v - 'a' + 10); \
                } else if (*_v >= 'A' && *_v <= 'F') { \
                    _dwSa = _dwSa * _base + (DWORD)(*_v - 'A' + 10); \
                } else { \
                    _tprintf(_T("%-12s : error parsing %s value, %s\n"), \
                             _T("??? (undef)"), name, _T(#value)); \
                    ExitProcess(EXIT_FAILURE); \
                } \
                _v++; \
            } \
            _show_sid(d, a, n, sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7, ph, phs, phn); \
        } \
    } while(0)

#define show_sid0(d, a) _show_sid(d, a, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0, 0)
#define show_sid1(d, a, sa0) _show_sid_ifdef(d, a, 1, _dwSa, 0, 0, 0, 0, 0, 0, 0, NULL, 0, 0, #sa0, sa0)
#define show_sid2(d, a, sa0, sa1) _show_sid_ifdef(d, a, 2, sa0, _dwSa, 0, 0, 0, 0, 0, 0, NULL, 0, 0, #sa1, sa1)
#define show_sid5(d, a, sa0, sa1, sa2, sa3, sa4) _show_sid_ifdef(d, a, 5, sa0, sa1, sa2, sa3, _dwSa, 0, 0, 0, NULL, 0, 0, #sa4, sa4)

/* Details S-1-5-21-a-b-c-RID SIDs, with placeholder */
#define show_nonunique_sid(desc, placeholder, rid) \
    _show_sid_ifdef(desc, &SIDAuthNt, 5, SECURITY_NT_NON_UNIQUE, 0, 0, 0, _dwSa, 0, 0, 0, placeholder, 4, 3, #rid, rid)

/* Details S-1-9-TYPE-LEVEL SIDs, with placeholder */
#define show_ppl_sid(desc, level) \
    _show_sid_ifdef(desc, &SIDAuthProcessTrust, 2, 0, level, 0, 0, _dwSa, 0, 0, 0, _T("type"), 3, 1, #level, level)

int _tmain(void)
{
    SID_IDENTIFIER_AUTHORITY SIDAuthNull = { SECURITY_NULL_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthLocal = { SECURITY_LOCAL_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthCreator = { SECURITY_CREATOR_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthNonUnique = { SECURITY_NON_UNIQUE_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthNt = { SECURITY_NT_AUTHORITY };

    show_sid1(_T("Null"), &SIDAuthNull, SECURITY_NULL_RID); /* S-1-0-0 */
    show_sid1(_T("World/Everyone"), &SIDAuthWorld, SECURITY_WORLD_RID); /* S-1-1-0 */

    show_sid1(_T("Local"), &SIDAuthLocal, SECURITY_LOCAL_RID); /* S-1-2-0 */
    show_sid1(_T("Local Logon"), &SIDAuthLocal, SECURITY_LOCAL_LOGON_RID); /* S-1-2-1 */

    show_sid1(_T("Creator Owner"), &SIDAuthCreator, SECURITY_CREATOR_OWNER_RID); /* S-1-3-0 */
    show_sid1(_T("Creator Group"), &SIDAuthCreator, SECURITY_CREATOR_GROUP_RID); /* S-1-3-1 */
    show_sid1(_T("Creator Owner Server"), &SIDAuthCreator, SECURITY_CREATOR_OWNER_SERVER_RID); /* S-1-3-2 */
    show_sid1(_T("Creator Group Server"), &SIDAuthCreator, SECURITY_CREATOR_GROUP_SERVER_RID); /* S-1-3-3 */
    show_sid1(_T("Creator Owner Rights"), &SIDAuthCreator, SECURITY_CREATOR_OWNER_RIGHTS_RID); /* S-1-3-4 */

    show_sid0(_T("Non-Unique Authority"), &SIDAuthNonUnique); /* S-1-4 */

    show_sid0(_T("NT Authority"), &SIDAuthNt); /* S-1-5 */
    show_sid1(_T("Dialup"), &SIDAuthNt, SECURITY_DIALUP_RID); /* S-1-5-1 */
    show_sid1(_T("Network"), &SIDAuthNt, SECURITY_NETWORK_RID); /* S-1-5-2 */
    show_sid1(_T("Batch"), &SIDAuthNt, SECURITY_BATCH_RID); /* S-1-5-3 */
    show_sid1(_T("Interactive"), &SIDAuthNt, SECURITY_INTERACTIVE_RID); /* S-1-5-4 */
    show_sid1(_T("Logon IDs prefix"), &SIDAuthNt, SECURITY_LOGON_IDS_RID); /* S-1-5-5 */
    show_sid1(_T("Service"), &SIDAuthNt, SECURITY_SERVICE_RID); /* S-1-5-6 */
    show_sid1(_T("Anonymous Logon"), &SIDAuthNt, SECURITY_ANONYMOUS_LOGON_RID); /* S-1-5-7 */
    show_sid1(_T("Proxy"), &SIDAuthNt, SECURITY_PROXY_RID); /* S-1-5-8 */
    show_sid1(_T("Enterprise Controllers"), &SIDAuthNt, SECURITY_ENTERPRISE_CONTROLLERS_RID); /* S-1-5-9 */
    show_sid1(_T("Principal Self"), &SIDAuthNt, SECURITY_PRINCIPAL_SELF_RID); /* S-1-5-10 */
    show_sid1(_T("Authenticated User"), &SIDAuthNt, SECURITY_AUTHENTICATED_USER_RID); /* S-1-5-11 */
    show_sid1(_T("Restricted Code"), &SIDAuthNt, SECURITY_RESTRICTED_CODE_RID); /* S-1-5-12 */
    show_sid1(_T("Terminal Server"), &SIDAuthNt, SECURITY_TERMINAL_SERVER_RID); /* S-1-5-13 */
    show_sid1(_T("Remote Logon"), &SIDAuthNt, SECURITY_REMOTE_LOGON_RID); /* S-1-5-14 */
    show_sid1(_T("This Organization"), &SIDAuthNt, SECURITY_THIS_ORGANIZATION_RID); /* S-1-5-15 */
    show_sid1(_T("IUser"), &SIDAuthNt, SECURITY_IUSER_RID); /* S-1-5-17 */
    show_sid1(_T("Local System"), &SIDAuthNt, SECURITY_LOCAL_SYSTEM_RID); /* S-1-5-18 */
    show_sid1(_T("Local Service"), &SIDAuthNt, SECURITY_LOCAL_SERVICE_RID); /* S-1-5-19 */
    show_sid1(_T("Network Service"), &SIDAuthNt, SECURITY_NETWORK_SERVICE_RID); /* S-1-5-20 */
    show_sid1(_T("Non-Unique"), &SIDAuthNt, SECURITY_NT_NON_UNIQUE); /* S-1-5-21 */

    /* Details S-1-5-21-a-b-c-RID SIDs */
    show_sid5(_T("Compounded Authentication"), &SIDAuthNt, SECURITY_NT_NON_UNIQUE, 0, 0, 0, DOMAIN_GROUP_RID_AUTHORIZATION_DATA_IS_COMPOUNDED); /* S-1-5-21-0-0-0-496 */
    show_sid5(_T("Claims Valid"), &SIDAuthNt, SECURITY_NT_NON_UNIQUE, 0, 0, 0, DOMAIN_GROUP_RID_AUTHORIZATION_DATA_CONTAINS_CLAIMS); /* S-1-5-21-0-0-0-497 */
    show_nonunique_sid(_T("Read-Only Domain Controllers Group"), _T("root domain"), DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS); /* S-1-5-21-<root domain>-498 */
    show_nonunique_sid(_T("Administrator"), _T("machine domain"), DOMAIN_USER_RID_ADMIN); /* S-1-5-21-<machine domain>-500 */
    show_nonunique_sid(_T("Guest"), _T("machine domain"), DOMAIN_USER_RID_GUEST); /* S-1-5-21-<machine domain>-501 */
    show_nonunique_sid(_T("Krbtgt"), _T("machine domain"), DOMAIN_USER_RID_KRBTGT); /* S-1-5-21-<machine domain>-502 */
    show_nonunique_sid(_T("Default Account"), _T("machine domain"), DOMAIN_USER_RID_DEFAULT_ACCOUNT); /* S-1-5-21-<machine domain>-503 */
    show_nonunique_sid(_T("WDAG (Windows Defender Application Guard) Account"), _T("machine domain"), DOMAIN_USER_RID_WDAG_ACCOUNT); /* S-1-5-21-<machine domain>-504 */
    show_nonunique_sid(_T("Domain Admins"), _T("domain"), DOMAIN_GROUP_RID_ADMINS); /* S-1-5-21-<domain>-512 */
    show_nonunique_sid(_T("Domain Users"), _T("domain"), DOMAIN_GROUP_RID_USERS); /* S-1-5-21-<domain>-513 */
    show_nonunique_sid(_T("Domain Guests"), _T("domain"), DOMAIN_GROUP_RID_GUESTS); /* S-1-5-21-<domain>-514 */
    show_nonunique_sid(_T("Domain Computers"), _T("domain"), DOMAIN_GROUP_RID_COMPUTERS); /* S-1-5-21-<domain>-515 */
    show_nonunique_sid(_T("Domain Controllers"), _T("domain"), DOMAIN_GROUP_RID_CONTROLLERS); /* S-1-5-21-<domain>-516 */
    show_nonunique_sid(_T("Domain Certificate Publishers"), _T("domain"), DOMAIN_GROUP_RID_CERT_ADMINS); /* S-1-5-21-<domain>-517 */
    show_nonunique_sid(_T("Schema Admins"), _T("domain"), DOMAIN_GROUP_RID_SCHEMA_ADMINS); /* S-1-5-21-<domain>-518 */
    show_nonunique_sid(_T("Entreprise Admins"), _T("domain"), DOMAIN_GROUP_RID_ENTERPRISE_ADMINS); /* S-1-5-21-<domain>-519 */
    show_nonunique_sid(_T("Group Policy Creator Owners"), _T("domain"), DOMAIN_GROUP_RID_POLICY_ADMINS); /* S-1-5-21-<domain>-520 */
    show_nonunique_sid(_T("Read-Only Domain Controllers"), _T("domain"), DOMAIN_GROUP_RID_READONLY_CONTROLLERS); /* S-1-5-21-<domain>-521 */
    show_nonunique_sid(_T("Clonable Domain Controllers"), _T("domain"), DOMAIN_GROUP_RID_CLONEABLE_CONTROLLERS); /* S-1-5-21-<domain>-522 */
    show_nonunique_sid(_T("Protected Users"), _T("domain"), DOMAIN_GROUP_RID_PROTECTED_USERS); /* S-1-5-21-<domain>-525 */
    show_nonunique_sid(_T("Key Admins"), _T("domain"), DOMAIN_GROUP_RID_KEY_ADMINS); /* S-1-5-21-<domain>-526 */
    show_nonunique_sid(_T("Enterprise Key Admins"), _T("domain"), DOMAIN_GROUP_RID_ENTERPRISE_KEY_ADMINS); /* S-1-5-21-<domain>-527 */
    show_nonunique_sid(_T("RAS (Remote Access Services) Servers"), _T("domain"), DOMAIN_ALIAS_RID_RAS_SERVERS); /* S-1-5-21-<domain>-553 */

    show_sid1(_T("Enterprise Read-Only Controllers"), &SIDAuthNt, SECURITY_ENTERPRISE_READONLY_CONTROLLERS_RID); /* S-1-5-22 */
    show_sid1(_T("Built-in System Domain"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID); /* S-1-5-32 */
    show_sid2(_T("Built-in Admin User"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_USER_RID_ADMIN); /* S-1-5-32-500 */
    show_sid2(_T("Built-in Guest User"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_USER_RID_GUEST); /* S-1-5-32-501 */
    show_sid2(_T("Built-in Krbtgt User"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_USER_RID_KRBTGT); /* S-1-5-32-502 */
    show_sid2(_T("Built-in Admins Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_ADMINS); /* S-1-5-32-512 */
    show_sid2(_T("Built-in Users Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_USERS); /* S-1-5-32-513 */
    show_sid2(_T("Built-in Guests Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_GUESTS); /* S-1-5-32-514 */
    show_sid2(_T("Built-in Computers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_COMPUTERS); /* S-1-5-32-515 */
    show_sid2(_T("Built-in Controllers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_CONTROLLERS); /* S-1-5-32-516 */
    show_sid2(_T("Built-in Certificate Publishers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_CERT_ADMINS); /* S-1-5-32-517 */
    show_sid2(_T("Built-in Schema Admins Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_SCHEMA_ADMINS); /* S-1-5-32-518 */
    show_sid2(_T("Built-in Enterprise Admins Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_ENTERPRISE_ADMINS); /* S-1-5-32-519 */
    show_sid2(_T("Built-in Policy Admins Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_POLICY_ADMINS); /* S-1-5-32-520 */
    show_sid2(_T("Built-in Read-Only Controllers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_READONLY_CONTROLLERS); /* S-1-5-32-521 */
    show_sid2(_T("Built-in Clonable Controllers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_GROUP_RID_CLONEABLE_CONTROLLERS); /* S-1-5-32-522 */
    show_sid2(_T("Built-in Administrators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS); /* S-1-5-32-544 */
    show_sid2(_T("Built-in Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS); /* S-1-5-32-545 */
    show_sid2(_T("Built-in Guests"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_GUESTS); /* S-1-5-32-546 */
    show_sid2(_T("Built-in Power Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS); /* S-1-5-32-547 */
    show_sid2(_T("Built-in Account Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ACCOUNT_OPS); /* S-1-5-32-548 */
    show_sid2(_T("Built-in System Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_SYSTEM_OPS); /* S-1-5-32-549 */
    show_sid2(_T("Built-in Printer Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PRINT_OPS); /* S-1-5-32-550 */
    show_sid2(_T("Built-in Backup Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_BACKUP_OPS); /* S-1-5-32-551 */
    show_sid2(_T("Built-in Replicator"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_REPLICATOR); /* S-1-5-32-552 */
    show_sid2(_T("Built-in RAS Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RAS_SERVERS); /* S-1-5-32-553 */
    show_sid2(_T("Built-in Pre Windows 2000 Compatible Access"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PREW2KCOMPACCESS); /* S-1-5-32-554 */
    show_sid2(_T("Built-in Remote Desktop Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS); /* S-1-5-32-555 */
    show_sid2(_T("Built-in Network Configuration Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS); /* S-1-5-32-556 */
    show_sid2(_T("Built-in Incoming Forest Trust Builders"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS); /* S-1-5-32-557 */
    show_sid2(_T("Built-in Perf Monitoring Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_MONITORING_USERS); /* S-1-5-32-558 */
    show_sid2(_T("Built-in Perf Logging Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_LOGGING_USERS); /* S-1-5-32-559 */
    show_sid2(_T("Built-in Authorization Access"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS); /* S-1-5-32-560 */
    show_sid2(_T("Built-in Terminal Server License Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS); /* S-1-5-32-561 */
    show_sid2(_T("Built-in DCOM Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_DCOM_USERS); /* S-1-5-32-562 */
    show_sid2(_T("Built-in Internet Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_IUSERS); /* S-1-5-32-568 */
    show_sid2(_T("Built-in Cryptographic Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_CRYPTO_OPERATORS); /* S-1-5-32-569 */
    show_sid2(_T("Built-in Cacheable Principals Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP); /* S-1-5-32-571 */
    show_sid2(_T("Built-in Non-Cacheable Principals Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP); /* S-1-5-32-572 */
    show_sid2(_T("Built-in Event Log Readers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP); /* S-1-5-32-573 */
    show_sid2(_T("Built-in CertSVC DCOM Access Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP); /* S-1-5-32-574 */
    show_sid2(_T("Built-in Remote Access Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RDS_REMOTE_ACCESS_SERVERS); /* S-1-5-32-575 */
    show_sid2(_T("Built-in Endpoint Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RDS_ENDPOINT_SERVERS); /* S-1-5-32-576 */
    show_sid2(_T("Built-in Management Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RDS_MANAGEMENT_SERVERS); /* S-1-5-32-577 */
    show_sid2(_T("Built-in Hyper V Admins"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_HYPER_V_ADMINS); /* S-1-5-32-578 */
    show_sid2(_T("Built-in Access Control Assistance Ops"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ACCESS_CONTROL_ASSISTANCE_OPS); /* S-1-5-32-579 */
    show_sid2(_T("Built-in Remote Management Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS); /* S-1-5-32-580 */

    show_sid1(_T("Write Restricted Code"), &SIDAuthNt, SECURITY_WRITE_RESTRICTED_CODE_RID); /* S-1-5-33 */

    show_sid2(_T("NTLM Authentication"), &SIDAuthNt, SECURITY_PACKAGE_BASE_RID, SECURITY_PACKAGE_NTLM_RID); /* S-1-5-64-10 */
    show_sid2(_T("SChannel Authentication"), &SIDAuthNt, SECURITY_PACKAGE_BASE_RID, SECURITY_PACKAGE_SCHANNEL_RID); /* S-1-5-64-14 */
    show_sid2(_T("Digest Authentication"), &SIDAuthNt, SECURITY_PACKAGE_BASE_RID, SECURITY_PACKAGE_DIGEST_RID); /* S-1-5-64-21 */

#ifdef SECURITY_CRED_TYPE_BASE_RID
    show_sid2(_T("This Organization Certificate"), &SIDAuthNt, SECURITY_CRED_TYPE_BASE_RID, SECURITY_CRED_TYPE_THIS_ORG_CERT_RID); /* S-1-5-65-1 */
#endif

    show_sid1(_T("NT Service Account prefix"), &SIDAuthNt, SECURITY_SERVICE_ID_BASE_RID); /* S-1-5-80 */
    show_sid1(_T("App Pool ID prefix"), &SIDAuthNt, SECURITY_APPPOOL_ID_BASE_RID); /* S-1-5-82 */
    show_sid1(_T("Virtual Service ID prefix"), &SIDAuthNt, SECURITY_VIRTUALSERVER_ID_BASE_RID); /* S-1-5-83 */
    show_sid1(_T("User Mode Driver ID prefix"), &SIDAuthNt, SECURITY_USERMODEDRIVERHOST_ID_BASE_RID); /* S-1-5-84 */
    show_sid1(_T("Cloud Infrastructure Services ID prefix"), &SIDAuthNt, SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_BASE_RID); /* S-1-5-85 */
    show_sid1(_T("WMI Host ID prefix"), &SIDAuthNt, SECURITY_WMIHOST_ID_BASE_RID); /* S-1-5-86 */
    show_sid1(_T("Task ID prefix"), &SIDAuthNt, SECURITY_TASK_ID_BASE_RID); /* S-1-5-87 */
    show_sid1(_T("NFS ID prefix"), &SIDAuthNt, SECURITY_NFS_ID_BASE_RID); /* S-1-5-88 */
    show_sid1(_T("COM ID prefix"), &SIDAuthNt, SECURITY_COM_ID_BASE_RID); /* S-1-5-89 */
    show_sid1(_T("Window Manager ID prefix"), &SIDAuthNt, SECURITY_WINDOW_MANAGER_BASE_RID); /* S-1-5-90 */
    show_sid1(_T("RDV GFX ID prefix"), &SIDAuthNt, SECURITY_RDV_GFX_BASE_RID); /* S-1-5-91 */
    show_sid1(_T("DAS Host ID prefix"), &SIDAuthNt, SECURITY_DASHOST_ID_BASE_RID); /* S-1-5-92 */

    show_sid1(_T("Windows Mobile ID prefix"), &SIDAuthNt, SECURITY_WINDOWSMOBILE_ID_BASE_RID); /* S-1-5-112 */
    show_sid1(_T("Local Accounts Group"), &SIDAuthNt, SECURITY_LOCAL_ACCOUNT_RID); /* S-1-5-113 */
    show_sid1(_T("Local Accounts Members of the Administrators Group"), &SIDAuthNt, SECURITY_LOCAL_ACCOUNT_AND_ADMIN_RID); /* S-1-5-114 */

    show_sid1(_T("Other Organization"), &SIDAuthNt, SECURITY_OTHER_ORGANIZATION_RID); /* S-1-5-1000 */

#ifdef SECURITY_RESOURCE_MANAGER_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthRsrcMan = { SECURITY_RESOURCE_MANAGER_AUTHORITY };
        show_sid0(_T("Resource Manager Authority"), &SIDAuthRsrcMan); /* S-1-9 */
    }
#endif
#ifdef SECURITY_APP_PACKAGE_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthAppPackage = { SECURITY_APP_PACKAGE_AUTHORITY };
        show_sid0(_T("App Package Authority"), &SIDAuthAppPackage); /* S-1-15 */
        show_sid2(_T("All App Packages"), &SIDAuthAppPackage, SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE); /* S-1-15-2-1 */
        show_sid2(_T("Any Restricted App Packages"), &SIDAuthAppPackage, SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE); /* S-1-15-2-2 */
    }
#endif
#ifdef SECURITY_MANDATORY_LABEL_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthMandatoryLabel = { SECURITY_MANDATORY_LABEL_AUTHORITY };
        show_sid0(_T("Mandatory Label Authority"), &SIDAuthMandatoryLabel); /* S-1-16 */
        show_sid1(_T("Untrusted Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_UNTRUSTED_RID); /* S-1-16-0 */
        show_sid1(_T("Low Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_LOW_RID); /* S-1-16-4096 */
        show_sid1(_T("Medium Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_MEDIUM_RID); /* S-1-16-8192 */
        show_sid1(_T("Medium Plus Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_MEDIUM_PLUS_RID); /* S-1-16-8448 */
        show_sid1(_T("High Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_HIGH_RID); /* S-1-16-12288 */
        show_sid1(_T("System Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_SYSTEM_RID); /* S-1-16-16384 */
        show_sid1(_T("Protected Process Integrity Level"), &SIDAuthMandatoryLabel, SECURITY_MANDATORY_PROTECTED_PROCESS_RID); /* S-1-16-20480 */
        show_sid1(_T("Secure Process Integrity Level"), &SIDAuthMandatoryLabel, 0x7000); /* S-1-16-28672 */
    }
#endif
#ifdef SECURITY_SCOPED_POLICY_ID_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthScopedPolicyId = { SECURITY_SCOPED_POLICY_ID_AUTHORITY };
        show_sid0(_T("Scoped Policy ID"), &SIDAuthScopedPolicyId); /* S-1-17 */
    }
#endif
#ifdef SECURITY_AUTHENTICATION_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthAuthentication = { SECURITY_AUTHENTICATION_AUTHORITY };
        show_sid0(_T("Authentication Authority"), &SIDAuthAuthentication); /* S-1-18 */
        show_sid1(_T("Authentication Authority Asserted Identity"), &SIDAuthAuthentication, SECURITY_AUTHENTICATION_AUTHORITY_ASSERTED_RID); /* S-1-18-1 */
        show_sid1(_T("Service Asserted Identity"), &SIDAuthAuthentication, SECURITY_AUTHENTICATION_SERVICE_ASSERTED_RID); /* S-1-18-2 */
        show_sid1(_T("Fresh Key Auth"), &SIDAuthAuthentication, SECURITY_AUTHENTICATION_FRESH_KEY_AUTH_RID); /* S-1-18-3 */
        show_sid1(_T("Key Trust"), &SIDAuthAuthentication, SECURITY_AUTHENTICATION_KEY_TRUST_RID); /* S-1-18-4 */
        show_sid1(_T("Key Property MFA"), &SIDAuthAuthentication, SECURITY_AUTHENTICATION_KEY_PROPERTY_MFA_RID); /* S-1-18-5 */
        show_sid1(_T("Key Property Attestation"), &SIDAuthAuthentication, SECURITY_AUTHENTICATION_KEY_PROPERTY_ATTESTATION_RID); /* S-1-18-6 */
    }
#endif
#ifdef SECURITY_PROCESS_TRUST_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthProcessTrust = { SECURITY_PROCESS_TRUST_AUTHORITY };
        show_sid0(_T("Process Trust Authority"), &SIDAuthProcessTrust); /* S-1-19 */
        show_sid1(_T("Process Protection Type None prefix"), &SIDAuthProcessTrust, SECURITY_PROCESS_PROTECTION_TYPE_NONE_RID); /* S-1-19-0 */
        show_sid1(_T("Process Protection Type Lite prefix"), &SIDAuthProcessTrust, SECURITY_PROCESS_PROTECTION_TYPE_LITE_RID); /* S-1-19-512 */
        show_sid1(_T("Process Protection Type Full prefix"), &SIDAuthProcessTrust, SECURITY_PROCESS_PROTECTION_TYPE_FULL_RID); /* S-1-19-1024 */
        show_ppl_sid(_T("Process Protection Level None"), SECURITY_PROCESS_PROTECTION_LEVEL_NONE_RID); /* S-1-19-<type>-0 */
        show_ppl_sid(_T("Process Protection Level Authenticode"), SECURITY_PROCESS_PROTECTION_LEVEL_AUTHENTICODE_RID); /* S-1-19-<type>-1024 */
        show_ppl_sid(_T("Process Protection Level Anti-Malware"), 1536); /* S-1-19-<type>-1536 */
        show_ppl_sid(_T("Process Protection Level App"), SECURITY_PROCESS_PROTECTION_LEVEL_APP_RID); /* S-1-19-<type>-2048 */
        show_ppl_sid(_T("Process Protection Level Windows"), SECURITY_PROCESS_PROTECTION_LEVEL_WINDOWS_RID); /* S-1-19-<type>-4096 */
        show_ppl_sid(_T("Process Protection Level Windows TCB"), SECURITY_PROCESS_PROTECTION_LEVEL_WINTCB_RID); /* S-1-19-<type>-8192 */
        show_sid2(_T("Process Protection Windows Lite"), &SIDAuthProcessTrust, SECURITY_PROCESS_PROTECTION_TYPE_LITE_RID, SECURITY_PROCESS_PROTECTION_LEVEL_WINDOWS_RID); /* S-1-19-512-4096 */
    }
#endif
    return 0;
}
