/**
 * Well-known security identifiers (SIDs) can be built with macros
 *
 * Documentation:
 * * MSDN articles "Well-known SIDs" and "SID Components"
 * * CreateWellKnownSid function
 * * Wine: http://source.winehq.org/git/wine.git/blob/HEAD:/dlls/advapi32/security.c
 *
 * To regenarate comments in main, use the following command:
 *    well_known_sids.exe > a.txt
 *    sed -n 's,^\(S-[-0-9]*\) *= *\([^\r]*\),s!\\(show_sid.*"\2".*;\\).*!\\1 /''* \1 *''/!,p' < a.txt > b.sed
 *    sed -f b.sed -i well_known_sids.c
 */
#include "common.h"
#include <sddl.h>

static void _show_sid(
    LPCTSTR szDesc, PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
    BYTE nSubAuthorityCount,
    DWORD dwSA0, DWORD dwSA1, DWORD dwSA2, DWORD dwSA3, DWORD dwSA4,
    DWORD dwSA5, DWORD dwSA6, DWORD dwSA7)
{
    PSID pSid = NULL;
    LPTSTR szSid = NULL;
    if (!AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount,
                                  dwSA0, dwSA1, dwSA2, dwSA3,
                                  dwSA4, dwSA5, dwSA6, dwSA7, &pSid)) {
        print_winerr(_T("AllocateAndInitializeSid"));
        exit(1);
    }
    assert(pSid);
    if (!ConvertSidToStringSid(pSid, &szSid)) {
        print_winerr(_T("ConvertSidToStringSid"));
        exit(1);
    }
    assert(szSid);
    _tprintf(_T("%-12s = %s\n"), szSid, szDesc);
    LocalFree(szSid);
}

/*
 * As some definitions may happen not to be defined, use preprocessor
 * stringification process to detect undefined constants.
 */
#define _show_sid_ifdef(d, a, n, sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7, name, value) \
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
                    _dwSa = _dwSa * _base + (DWORD)(*_v - 'a'); \
                } else if (*_v >= 'A' && *_v <= 'F') { \
                    _dwSa = _dwSa * _base + (DWORD)(*_v - 'A'); \
                } else { \
                    _tprintf(_T("%-12s : error parsing %s value, %s\n"), \
                             _T("??? (undef)"), name, _T(#value)); \
                    ExitProcess(EXIT_FAILURE); \
                } \
                _v++; \
            } \
            _show_sid(d, a, n, sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7); \
        } \
    } while(0)

#define show_sid0(d, a) _show_sid(d, a, 0, 0, 0, 0, 0, 0, 0, 0, 0)
#define show_sid1(d, a, sa0) _show_sid_ifdef(d, a, 1, _dwSa, 0, 0, 0, 0, 0, 0, 0, #sa0, sa0)
#define show_sid2(d, a, sa0, sa1) _show_sid_ifdef(d, a, 2, sa0, _dwSa, 0, 0, 0, 0, 0, 0, #sa1, sa1)

int _tmain(void)
{
    SID_IDENTIFIER_AUTHORITY SIDAuthNull = { SECURITY_NULL_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthLocal = { SECURITY_LOCAL_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthCreator = { SECURITY_CREATOR_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthNonUnique = { SECURITY_NON_UNIQUE_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthNt = { SECURITY_NT_AUTHORITY };

    show_sid1(_T("Null"), &SIDAuthNull, SECURITY_NULL_RID); /* S-1-0-0 */
    show_sid1(_T("World"), &SIDAuthWorld, SECURITY_WORLD_RID); /* S-1-1-0 */
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
    show_sid2(_T("Built-in Print Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PRINT_OPS); /* S-1-5-32-550 */
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
    show_sid2(_T("Built-in Crypto Operators"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_CRYPTO_OPERATORS); /* S-1-5-32-569 */
    show_sid2(_T("Built-in Cacheable Principals Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP); /* S-1-5-32-571 */
    show_sid2(_T("Built-in Non-Cacheable Principals Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP); /* S-1-5-32-572 */
    show_sid2(_T("Built-in Log Readers Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP); /* S-1-5-32-573 */
    show_sid2(_T("Built-in CertSVC DCOM Access Group"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP); /* S-1-5-32-574 */
    show_sid2(_T("Built-in Remote Access Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RDS_REMOTE_ACCESS_SERVERS); /* S-1-5-32-575 */
    show_sid2(_T("Built-in Endpoint Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RDS_ENDPOINT_SERVERS); /* S-1-5-32-576 */
    show_sid2(_T("Built-in Management Servers"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_RDS_MANAGEMENT_SERVERS); /* S-1-5-32-577 */
    show_sid2(_T("Built-in Hyper V Admins"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_HYPER_V_ADMINS); /* S-1-5-32-578 */
    show_sid2(_T("Built-in Access Control Assistance Ops"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ACCESS_CONTROL_ASSISTANCE_OPS); /* S-1-5-32-579 */
    show_sid2(_T("Built-in Remote Management Users"), &SIDAuthNt, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS); /* S-1-5-32-580 */
    show_sid1(_T("Other Organization"), &SIDAuthNt, SECURITY_OTHER_ORGANIZATION_RID); /* S-1-5-1000 */
#ifdef SECURITY_RESOURCE_MANAGER_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthRsrcMan = { SECURITY_RESOURCE_MANAGER_AUTHORITY };
        show_sid0(_T("Resource Manager Authority"), &SIDAuthRsrcMan); /* S-1-9 */
    }
#endif
#ifdef SECURITY_MANDATORY_LABEL_AUTHORITY
    {
        SID_IDENTIFIER_AUTHORITY SIDAuthMandatoryLabel = { SECURITY_MANDATORY_LABEL_AUTHORITY };
        show_sid0(_T("Mandatory Label Authority"), &SIDAuthMandatoryLabel); /* S-1-16 */
    }
#endif
    return 0;
}
