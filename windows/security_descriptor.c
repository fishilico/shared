/**
 * Display information about a security descriptor provided using SDDL
 * (Security Descriptor Definition Language)
 *
 * This is like icacls.exe or PowerShell Get-Acl, but more verbose.
 *
 * Syntax of "D:(D;OICI;GA;;;BG)":
 * * Security Descriptor part "D": DACL (can be "O" for owner SID, "G" for primary group SID, "S" for SACL)
 * * ACE (Access Control Entry) type "D": Deny (can be "A" for allow, "AU" for audit, etc.)
 * * ACE flags "OICI": OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
 * * ACE rights "GA": GENERIC_ALL
 * * ACE object GUID ""
 * * ACE inherit object GUID ""
 * * ACE account SID
 *
 * Documentation:
 * * https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
 *   Security Descriptor String Format
 * * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
 *   [MS-DTYP]: Windows Data Types, 2.4.6 SECURITY_DESCRIPTOR
 * * https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw
 *   Parse a string-format security descriptor (with version SDDL_REVISION_1 = 1)
 */
#include "common.h"
#include <aclapi.h>
#include <iads.h>
#include <ntsecapi.h>
#include <sddl.h>

/* Define some constants that were missing on ancient SDK headers */
#ifndef SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
#    define SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE 0x12
#endif
#ifndef SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
#    define SYSTEM_SCOPED_POLICY_ID_ACE_TYPE 0x13
#endif
#ifndef BACKUP_SECURITY_INFORMATION
#    define BACKUP_SECURITY_INFORMATION 0x00010000
#endif
#ifndef SCOPE_SECURITY_INFORMATION
#    define SCOPE_SECURITY_INFORMATION 0x00000040
#endif

/* Examples of security descriptors that are analyzed by default */
static const TCHAR *const g_example_security_descriptors[] = {
    /* DACL: Allow GENERIC_ALL for Built-in Administrators
     * SACL: Audit successful access attempts and failed access attempts for all kinds of file access, for the World
     */
    _T("D:(A;OICI;GA;;;BA)S:ARAI(AU;SAFA;FA;;;WD)"),

    /* DACL:
     * * Deny GENERIC_ALL for Built-in Guests
     * * Deny GENERIC_ALL for Anonymous Logon
     * * Allow GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE for Authenticated Users
     * * Allow GENERIC_ALL for Built-in Administrators
     */
    _T("D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)"),

    /* SACL: Mandatory Label No Write Up for Low Integrity Level */
    _T("S:(ML;;NW;;;LW)"),

    /* Owner: Built-in Account Operators ("AO")
     * Primary Group: Built-in Administrators ("BA")
     * DACL: Allow ADS_RIGHT_DS_{READ_PROP|WRITE_PROP|CREATE_CHILD|DELETE_CHILD|LIST|SELF_WRITE}|
     *     READ_CONTROL|WRITE_DACL|WRITE_OWNER|GENERIC_ALL for Null
     */
    _T("O:AOG:BAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"),

    /* SDDL for C:
     * DACL:
     * * DACL Protected and Auto-Inherited ("PAI")
     * * Allow FILE_ALL_ACCESS for Built-in Administrators ("BA")
     * * Allow FILE_ALL_ACCESS for Local System ("SY")
     * * Allow FILE_GENERIC_READ|FILE_GENERIC_EXECUTE for Built-in Users ("BU")
     * * (Inherit only) Allow DELETE|GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ for Authenticated Users ("AU")
     * * Allow ADS_RIGHT_ACTRL_DS_LIST for Authenticated Users ("AU")
     * SACL: (No Propagate Inherit) No Write UP for High Integrity Level
     */
    _T("D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;LC;;;AU)S:P(ML;OINPIO;NW;;;HI)"),

    /* SDDL for a registry key
     * Owner: Built-in Administrators ("BA")
     * Primary Group: Built-in Administrators ("BA")
     * DACL:
     * * Allow GENERIC_READ for Built-in Users
     * * Allow KEY_ALL_ACCESS for Built-in Administrators
     */
    _T("O:BAG:BAD:(A;CIIO;GR;;;BU)(A;;KA;;;BA)"),
};

/**
 * Well-known SIDs from Wine's advapi32.dll implementation:
 * https://source.winehq.org/git/wine.git/blob/HEAD:/dlls/advapi32/security.c
 * and from Microsoft documentation:
 * https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
 */
struct WELL_KNOWN_SID_DESC {
    LPCTSTR pszSid;
    LPCTSTR pszDesc;
};
static const struct WELL_KNOWN_SID_DESC g_well_known_sids[] = {
    {_T("S-1-0-0"), _T("Null")},
    {_T("S-1-1-0"), _T("WD (World/Everyone)")},
    {_T("S-1-3-0"), _T("CO (Creator Owner)")},
    {_T("S-1-3-1"), _T("CG (Creator Group)")},
    {_T("S-1-5-2"), _T("NU (Network logon User)")},
    {_T("S-1-5-4"), _T("IU (Interactively logged-on User)")},
    {_T("S-1-5-6"), _T("SU (Service logon User)")},
    {_T("S-1-5-7"), _T("AN (Anonymous)")},
    {_T("S-1-5-9"), _T("ED (Enterprise Domain Controllers)")},
    {_T("S-1-5-10"), _T("PS (Principal Self)")},
    {_T("S-1-5-11"), _T("AU (Authenticated Users)")},
    {_T("S-1-5-12"), _T("RC (Restricted Code)")},
    {_T("S-1-5-18"), _T("SY (Local System)")},
    {_T("S-1-5-19"), _T("LS (Local Service)")},
    {_T("S-1-5-20"), _T("NS (Network Service)")},
    {_T("S-1-5-32-544"), _T("BA (Built-in Administrators)")},
    {_T("S-1-5-32-545"), _T("BU (Built-in Users)")},
    {_T("S-1-5-32-546"), _T("BG (Built-in Guests)")},
    {_T("S-1-5-32-547"), _T("PU (Built-in Power Users)")},
    {_T("S-1-5-32-548"), _T("AO (Built-in Account Operators)")},
    {_T("S-1-5-32-549"), _T("SO (Built-in System/Server Operators)")},
    {_T("S-1-5-32-550"), _T("PO (Built-in Printer Operators)")},
    {_T("S-1-5-32-551"), _T("BO (Built-in Backup Operators)")},
    {_T("S-1-5-32-552"), _T("RE (Built-in Replicator)")},
    {_T("S-1-5-32-554"), _T("RU (Built-in Pre Windows 2000 Compatible Access)")},
    {_T("S-1-5-32-555"), _T("RD (Built-in Remote Desktop Users)")},
    {_T("S-1-5-32-556"), _T("NO (Built-in Network Configuration Operators)")},
    {_T("S-1-5-32-558"), _T("MU (Built-in Performance Monitoring Users)")},
    {_T("S-1-5-32-574"), _T("CD (Built-in CertSVC (Certificate Service) DCOM Access Group)")},

    /* NT Service Account
     * The SID is "S-1-5-80-SHA1(uppercase name in UTF-16LE)"
     * For example in Python:
     *     >>> struct.unpack('<5I', hashlib.sha1('TRUSTEDINSTALLER'.encode('utf-16le')).digest())
     *     (956008885, 3418522649, 1831038044, 1853292631, 2271478464)
     */
    {
        _T("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
        _T("(TrustedInstaller)"),
    },

    {_T("S-1-15-2-1"), _T("AC (All App Packages)")},
    {_T("S-1-15-2-2"), _T("(All Restricted App Packages)")},

    /* LPAC capabilities, Low Privilege AppContainer
     * The SID is "S-1-15-3-1024-SHA256(uppercase name in UTF-16LE)"
     * For example in Python:
     *     >>> struct.unpack('<8I', hashlib.sha256('REGISTRYREAD'.encode('utf-16le')).digest())
     *     (1065365936, 1281604716, 3511738428, 1654721687, 432734479, 3232135806, 4053264122, 3456934681)
     *
     * List of capabilities defined in Process Hacker:
     * https://github.com/processhacker/processhacker/blob/master/ProcessHacker/resources/capslist.txt
     */
    {
        _T("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"),
        _T("(LPAC registryRead)"),
    },
    {
        _T("S-1-15-3-1024-3635283841-2530182609-996808640-1887759898-3848208603-3313616867-983405619-2501854204"),
        _T("(LPAC packageContents)"),
    },

    {_T("S-1-16-4096"), _T("LW (Low Integrity Level)")},
    {_T("S-1-16-8192"), _T("ME (Medium Integrity Level)")},
    {_T("S-1-16-12288"), _T("HI (High Integrity Level)")},
    {_T("S-1-16-16384"), _T("SI (System Integrity Level)")},

    /* Relative SIDs */
    {_T("S-1-5-21-0-0-0-498"), _T("RO (Enterprise Read-Only Domain Controllers Group)")},
    {_T("S-1-5-21-0-0-0-500"), _T("LA (Local Administrator)")},
    {_T("S-1-5-21-0-0-0-501"), _T("LG (Local Guest)")},
    {_T("S-1-5-21-0-0-0-512"), _T("DA (Domain Admins)")},
    {_T("S-1-5-21-0-0-0-513"), _T("DU (Domain Users)")},
    {_T("S-1-5-21-0-0-0-514"), _T("DG (Domain Guests)")},
    {_T("S-1-5-21-0-0-0-515"), _T("DC (Domain Computers)")},
    {_T("S-1-5-21-0-0-0-516"), _T("DD (Domain Controllers)")},
    {_T("S-1-5-21-0-0-0-517"), _T("CA (Domain Certificate Publishers (Admins))")},
    {_T("S-1-5-21-0-0-0-518"), _T("SA (Schema Administrators)")},
    {_T("S-1-5-21-0-0-0-519"), _T("EA (Entreprise Admins)")},
    {_T("S-1-5-21-0-0-0-520"), _T("PA (Group Policy Creator Owners (Admins))")},
    {_T("S-1-5-21-0-0-0-553"), _T("RS (RAS (Remote Access Services) Servers)")},
};

/**
 * Display a SID (Security Identifier)
 */
static BOOL display_sid(LPCTSTR pszPrefix, SID *pSid)
{
    LPTSTR pszSid = NULL;
    LPCTSTR pszSidDesc = NULL;
    size_t iWellKnownSid;

    if (!ConvertSidToStringSid(pSid, &pszSid)) {
        print_winerr(_T("ConvertSidToStringSid"));
        return FALSE;
    }
    for (iWellKnownSid = 0; iWellKnownSid < ARRAYSIZE(g_well_known_sids); iWellKnownSid++) {
        if (!_tcscmp(pszSid, g_well_known_sids[iWellKnownSid].pszSid)) {
            pszSidDesc = g_well_known_sids[iWellKnownSid].pszDesc;
            break;
        }
    }
    if (pszSidDesc) {
        _tprintf(_T("%s%s = %s\n"), pszPrefix, pszSid, pszSidDesc);
    } else {
        _tprintf(_T("%s%s\n"), pszPrefix, pszSid);
    }
    LocalFree(pszSid);
    return TRUE;
}

/**
 * Display an ACL object
 */
static BOOL analyze_acl(const ACL *pDacl, UINT_PTR upAddrLimit, char cAclType)
{
    UINT_PTR upOffset = (UINT_PTR)pDacl, upDaclLimit;
    PACE_HEADER pAceHeader;
    unsigned int iEntry, iData;
    LPCTSTR pszAceType;
    UINT32 uAccessMask, uRemaining, uRemainingMask;

    assert(cAclType == 'D' || cAclType == 'S');

    _tprintf(_T("    AclRevision: %u (%s)\n"), pDacl->AclRevision,
             (pDacl->AclRevision == ACL_REVISION) ? _T("ACL_REVISION") : /* =2 */
             ((pDacl->AclRevision == ACL_REVISION_DS) ? _T("ACL_REVISION_DS") : /* =4 */
              _T("?")));
    if (pDacl->Sbz1) {
        _tprintf(_T("    Sbz1: %#x\n"), pDacl->Sbz1);
    }
    _tprintf(_T("    AclSize: %#x\n"), pDacl->AclSize);
    _tprintf(_T("    AceCount: %u\n"), pDacl->AceCount);
    if (pDacl->Sbz2) {
        _tprintf(_T("    Sbz2: %#x\n"), pDacl->Sbz2);
    }
    upDaclLimit = upOffset + pDacl->AclSize;
    assert(pDacl->AclSize >= 8);
    if (upAddrLimit != 0) {
        assert(upDaclLimit <= upAddrLimit); /* Ensure that the size is consistent */
    }

    upOffset += 8;
    for (iEntry = 0; iEntry < pDacl->AceCount; iEntry++) {
        /* Parse the ACE header */
        assert(sizeof(ACE_HEADER) == 4);
        assert(upOffset + 4 <= upDaclLimit);
        pAceHeader = (PACE_HEADER)upOffset;
        pszAceType = _T("Unknown");
        if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            pszAceType = _T("A (ACCESS_ALLOWED_ACE_TYPE)"); /* 0 */
        } else if (pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
            pszAceType = _T("D (ACCESS_DENIED_ACE_TYPE)"); /* 1 */
        } else if (pAceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE) {
            pszAceType = _T("AU (SYSTEM_AUDIT_ACE_TYPE)"); /* 2 */
        } else if (pAceHeader->AceType == SYSTEM_ALARM_ACE_TYPE) {
            pszAceType = _T("AL (SYSTEM_ALARM_ACE_TYPE)"); /* 3 */
        } else if (pAceHeader->AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE) { /* MS v3 ACE: 4 */
            pszAceType = _T("(ACCESS_ALLOWED_COMPOUND_ACE_TYPE)"); /* 4 */
        } else if (pAceHeader->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) { /* MS v4 ACE: 5, 6, 7, 8 */
            pszAceType = _T("OA (ACCESS_ALLOWED_OBJECT_ACE_TYPE)"); /* 5 */
        } else if (pAceHeader->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) {
            pszAceType = _T("OD (ACCESS_DENIED_OBJECT_ACE_TYPE)"); /* 6 */
        } else if (pAceHeader->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
            pszAceType = _T("OU (SYSTEM_AUDIT_OBJECT_ACE_TYPE)"); /* 7 */
        } else if (pAceHeader->AceType == SYSTEM_ALARM_OBJECT_ACE_TYPE) {
            pszAceType = _T("OL (SYSTEM_ALARM_OBJECT_ACE_TYPE)"); /* 8 */
        } else if (pAceHeader->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) { /* MS v5 ACE: 9, ... 0x13 */
            pszAceType = _T("XA (ACCESS_ALLOWED_CALLBACK_ACE_TYPE)"); /* 9 */
        } else if (pAceHeader->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE) {
            pszAceType = _T("XD (ACCESS_DENIED_CALLBACK_ACE_TYPE)"); /* 0x0a */
        } else if (pAceHeader->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
            pszAceType = _T("ZA (ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE)"); /* 0x0b */
        } else if (pAceHeader->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) {
            pszAceType = _T("(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)"); /* 0x0c */
        } else if (pAceHeader->AceType == SYSTEM_AUDIT_CALLBACK_ACE_TYPE) {
            pszAceType = _T("XU (SYSTEM_AUDIT_CALLBACK_ACE_TYPE)"); /* 0x0d */
        } else if (pAceHeader->AceType == SYSTEM_ALARM_CALLBACK_ACE_TYPE) {
            pszAceType = _T("(SYSTEM_ALARM_CALLBACK_ACE_TYPE)"); /* 0x0e */
        } else if (pAceHeader->AceType == SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE) {
            pszAceType = _T("(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE)"); /* 0x0f */
        } else if (pAceHeader->AceType == SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE) {
            pszAceType = _T("(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE)"); /* 0x10 */
        } else if (pAceHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
            pszAceType = _T("ML (SYSTEM_MANDATORY_LABEL_ACE_TYPE)"); /* 0x11 */
        } else if (pAceHeader->AceType == SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE) {
            pszAceType = _T("RA (SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE)"); /* 0x12 */
        } else if (pAceHeader->AceType == SYSTEM_SCOPED_POLICY_ID_ACE_TYPE) {
            pszAceType = _T("SP (SYSTEM_SCOPED_POLICY_ID_ACE_TYPE)"); /* 0x13 */
        }
        _tprintf(_T("    ACE %u:\n"), iEntry);
        _tprintf(_T("      AceType: %#lx = %s\n"), (ULONG)pAceHeader->AceType, pszAceType);
        _tprintf(_T("      AceFlags: %#lx\n"), (ULONG)pAceHeader->AceFlags);
        assert(OBJECT_INHERIT_ACE == 0x01);
        _tprintf(_T("        [%02x] %c OI (OBJECT_INHERIT_ACE)\n"),
                 OBJECT_INHERIT_ACE, (pAceHeader->AceFlags & OBJECT_INHERIT_ACE) ? '+' : '-');
        assert(CONTAINER_INHERIT_ACE == 0x02);
        _tprintf(_T("        [%02x] %c CI (CONTAINER_INHERIT_ACE)\n"),
                 CONTAINER_INHERIT_ACE, (pAceHeader->AceFlags & CONTAINER_INHERIT_ACE) ? '+' : '-');
        assert(NO_PROPAGATE_INHERIT_ACE == 0x04);
        _tprintf(_T("        [%02x] %c NP (NO_PROPAGATE_INHERIT_ACE)\n"),
                 NO_PROPAGATE_INHERIT_ACE, (pAceHeader->AceFlags & NO_PROPAGATE_INHERIT_ACE) ? '+' : '-');
        assert(INHERIT_ONLY_ACE == 0x08);
        _tprintf(_T("        [%02x] %c IO (INHERIT_ONLY_ACE)\n"),
                 INHERIT_ONLY_ACE, (pAceHeader->AceFlags & INHERIT_ONLY_ACE) ? '+' : '-');
        assert(INHERITED_ACE == 0x10);
        _tprintf(_T("        [%02x] %c ID (INHERITED_ACE)\n"),
                 INHERITED_ACE, (pAceHeader->AceFlags & INHERITED_ACE) ? '+' : '-');
        if (cAclType == 'S') {
            /* Flags specific to SACL */
            if (pAceHeader->AceFlags & 0x20) {
                _tprintf(_T("        [20] %#04x\n"), pAceHeader->AceFlags & 0x20);
            }
            assert(SUCCESSFUL_ACCESS_ACE_FLAG == 0x40);
            _tprintf(_T("        [%02x] %c SA (SUCCESSFUL_ACCESS_ACE_FLAG)\n"),
                     SUCCESSFUL_ACCESS_ACE_FLAG, (pAceHeader->AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) ? '+' : '-');
            assert(FAILED_ACCESS_ACE_FLAG == 0x80);
            _tprintf(_T("        [%02x] %c FA (FAILED_ACCESS_ACE_FLAG)\n"),
                     FAILED_ACCESS_ACE_FLAG, (pAceHeader->AceFlags & FAILED_ACCESS_ACE_FLAG) ? '+' : '-');
        } else {
            if (pAceHeader->AceFlags & 0xe0) {
                _tprintf(_T("        [e0] %#04x\n"), pAceHeader->AceFlags & 0xe0);
            }
        }
        _tprintf(_T("      AceSize: %#lx\n"), (ULONG)pAceHeader->AceSize);
        assert(pAceHeader->AceSize >= 4);
        assert(upOffset + pAceHeader->AceSize <= upDaclLimit);

        if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE ||
            pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE ||
            pAceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE ||
            pAceHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {

            /* Format: ACE_HEADER (4 bytes), ACCESS_MASK (4 bytes), SID (variable) */
            assert(pAceHeader->AceSize >= 4 + 4 + 8);
            assert(sizeof(uAccessMask) == 4);
            memcpy(&uAccessMask, (void *)(upOffset + 4), 4);
            _tprintf(_T("      Access Mask: %#010x\n"), uAccessMask);

            if (pAceHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE && (uAccessMask & 0xffff0000) == 0) {
                /* Mandatory label ACE usually only have low bits set. Do not display high bits */
            } else {
                assert(GENERIC_READ == 0x80000000);
                _tprintf(_T("        [%08lx] %c GR (GENERIC_READ)\n"),
                         GENERIC_READ, (uAccessMask & GENERIC_READ) ? '+' : '-');
                assert(GENERIC_WRITE == 0x40000000);
                _tprintf(_T("        [%08lx] %c GW (GENERIC_WRITE)\n"),
                         GENERIC_WRITE, (uAccessMask & GENERIC_WRITE) ? '+' : '-');
                assert(GENERIC_EXECUTE == 0x20000000);
                _tprintf(_T("        [%08lx] %c GX (GENERIC_EXECUTE)\n"),
                         GENERIC_EXECUTE, (uAccessMask & GENERIC_EXECUTE) ? '+' : '-');
                assert(GENERIC_ALL == 0x10000000);
                _tprintf(_T("        [%08lx] %c GA (GENERIC_ALL)\n"),
                         GENERIC_ALL, (uAccessMask & GENERIC_ALL) ? '+' : '-');
                assert(MAXIMUM_ALLOWED == 0x02000000);
                _tprintf(_T("        [%08lx] %c MA (MAXIMUM_ALLOWED)\n"),
                         MAXIMUM_ALLOWED, (uAccessMask & MAXIMUM_ALLOWED) ? '+' : '-');
                assert(ACCESS_SYSTEM_SECURITY == 0x01000000);
                _tprintf(_T("        [%08lx] %c AS (ACCESS_SYSTEM_SECURITY)\n"),
                         ACCESS_SYSTEM_SECURITY, (uAccessMask & ACCESS_SYSTEM_SECURITY) ? '+' : '-');
                assert(SYNCHRONIZE == 0x00100000);
                _tprintf(_T("        [%08lx] %c SY (SYNCHRONIZE)\n"),
                         SYNCHRONIZE, (uAccessMask & SYNCHRONIZE) ? '+' : '-');
                assert(WRITE_OWNER == 0x00080000);
                _tprintf(_T("        [%08lx] %c WO (WRITE_OWNER)\n"),
                         WRITE_OWNER, (uAccessMask & WRITE_OWNER) ? '+' : '-');
                assert(WRITE_DAC == 0x00040000);
                _tprintf(_T("        [%08lx] %c WD (WRITE_DAC/WRITE_DACL)\n"),
                         WRITE_DAC, (uAccessMask & WRITE_DAC) ? '+' : '-');
                assert(READ_CONTROL == 0x00020000);
                _tprintf(_T("        [%08lx] %c RC (READ_CONTROL)\n"),
                         READ_CONTROL, (uAccessMask & READ_CONTROL) ? '+' : '-');
                assert(DELETE == 0x00010000);
                _tprintf(_T("        [%08lx] %c SD ((STANDARD_) DELETE)\n"),
                         DELETE, (uAccessMask & DELETE) ? '+' : '-');
                uRemaining = uAccessMask & ~0xf31fffff;
                if (uRemaining) {
                    _tprintf(_T("        [%08x] ? %#010x\n"), 0xffffffff & ~0xf31fffff, uRemaining);
                }
            }
            /* Specific rights are in the 16 low bits */
            assert(SPECIFIC_RIGHTS_ALL == 0x0000ffff);
            uRemainingMask = SPECIFIC_RIGHTS_ALL;
            if (pAceHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                /* Mandatory label ACE */
                assert(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP == 1);
                _tprintf(_T("        [%08x] %c NW (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP)\n"),
                         SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                         (uAccessMask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) ? '+' : '-');
                assert(SYSTEM_MANDATORY_LABEL_NO_READ_UP == 2);
                _tprintf(_T("        [%08x] %c NR (SYSTEM_MANDATORY_LABEL_NO_READ_UP)\n"),
                         SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                         (uAccessMask & SYSTEM_MANDATORY_LABEL_NO_READ_UP) ? '+' : '-');
                assert(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP == 4);
                _tprintf(_T("        [%08x] %c NX (SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)\n"),
                         SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
                         (uAccessMask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) ? '+' : '-');
                uRemainingMask &= ~7;
            }
            if (uAccessMask & uRemainingMask) {
                _tprintf(_T("        [    %04x] %#06x Specific Rights\n"),
                         uRemainingMask, uAccessMask & uRemainingMask);
                assert(FILE_ALL_ACCESS == 0x001f01ff);
                if ((uAccessMask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) {
                    _tprintf(_T("        [%08lx] + FA (FILE_ALL_ACCESS)\n"), FILE_ALL_ACCESS);
                }
                assert(FILE_GENERIC_READ == 0x00120089);
                if ((uAccessMask & FILE_GENERIC_READ) == FILE_GENERIC_READ) {
                    _tprintf(_T("        [%08lx] + FR (FILE_GENERIC_READ)\n"), FILE_GENERIC_READ);
                }
                assert(FILE_GENERIC_WRITE == 0x00120116);
                if ((uAccessMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) {
                    _tprintf(_T("        [%08lx] + FW (FILE_GENERIC_WRITE)\n"), FILE_GENERIC_WRITE);
                }
                assert(FILE_GENERIC_EXECUTE == 0x001200a0);
                if ((uAccessMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) {
                    _tprintf(_T("        [%08lx] + FX (FILE_GENERIC_EXECUTE)\n"), FILE_GENERIC_EXECUTE);
                }
                assert(FILE_READ_DATA == 0x00000001);
                assert(FILE_LIST_DIRECTORY == 0x00000001);
                if (uAccessMask & FILE_READ_DATA) {
                    _tprintf(_T("        [    %04x] +    (FILE_READ_DATA, FILE_LIST_DIRECTORY)\n"), FILE_READ_DATA);
                }
                assert(FILE_WRITE_DATA == 0x00000002);
                assert(FILE_ADD_FILE == 0x00000002);
                if (uAccessMask & FILE_WRITE_DATA) {
                    _tprintf(_T("        [    %04x] +    (FILE_WRITE_DATA, FILE_ADD_FILE)\n"), FILE_WRITE_DATA);
                }
                assert(FILE_APPEND_DATA == 0x00000004);
                assert(FILE_ADD_SUBDIRECTORY == 0x00000004);
                assert(FILE_CREATE_PIPE_INSTANCE == 0x00000004);
                if (uAccessMask & FILE_APPEND_DATA) {
                    _tprintf(
                        _T("        [    %04x] +    (FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY, FILE_CREATE_PIPE_INSTANCE)\n"),
                        FILE_APPEND_DATA);
                }
                assert(FILE_READ_EA == 0x00000008);
                if (uAccessMask & FILE_READ_EA) {
                    _tprintf(_T("        [    %04x] +    (FILE_READ_EA)\n"), FILE_READ_EA);
                }
                assert(FILE_WRITE_EA == 0x00000010);
                if (uAccessMask & FILE_WRITE_EA) {
                    _tprintf(_T("        [    %04x] +    (FILE_WRITE_EA)\n"), FILE_WRITE_EA);
                }
                assert(FILE_EXECUTE == 0x00000020);
                assert(FILE_TRAVERSE == 0x00000020);
                if (uAccessMask & FILE_EXECUTE) {
                    _tprintf(_T("        [    %04x] +    (FILE_EXECUTE, FILE_TRAVERSE)\n"), FILE_EXECUTE);
                }
                assert(FILE_DELETE_CHILD == 0x00000040);
                if (uAccessMask & FILE_DELETE_CHILD) {
                    _tprintf(_T("        [    %04x] +    (FILE_DELETE_CHILD)\n"), FILE_DELETE_CHILD);
                }
                assert(FILE_READ_ATTRIBUTES == 0x00000080);
                if (uAccessMask & FILE_READ_ATTRIBUTES) {
                    _tprintf(_T("        [    %04x] +    (FILE_READ_ATTRIBUTES)\n"), FILE_READ_ATTRIBUTES);
                }
                assert(FILE_WRITE_ATTRIBUTES == 0x00000100);
                if (uAccessMask & FILE_WRITE_ATTRIBUTES) {
                    _tprintf(_T("        [    %04x] +    (FILE_WRITE_ATTRIBUTES)\n"), FILE_WRITE_ATTRIBUTES);
                }

                assert(KEY_ALL_ACCESS == 0x000f003f);
                if ((uAccessMask & KEY_ALL_ACCESS) == KEY_ALL_ACCESS) {
                    _tprintf(_T("        [%08lx] + KA (KEY_ALL_ACCESS)\n"), KEY_ALL_ACCESS);
                }
                assert(KEY_READ == 0x00020019);
                assert(KEY_EXECUTE == 0x00020019);
                if ((uAccessMask & KEY_READ) == KEY_READ) {
                    _tprintf(_T("        [%08lx] + KR (KEY_READ), KX (KEY_EXECUTE)\n"), KEY_READ);
                }
                assert(KEY_WRITE == 0x00020006);
                if ((uAccessMask & KEY_WRITE) == KEY_WRITE) {
                    _tprintf(_T("        [%08lx] + KW (KEY_WRITE)\n"), KEY_WRITE);
                }
                assert(KEY_QUERY_VALUE == 0x00000001);
                if (uAccessMask & KEY_QUERY_VALUE) {
                    _tprintf(_T("        [    %04x] +    (KEY_QUERY_VALUE)\n"), KEY_QUERY_VALUE);
                }
                assert(KEY_SET_VALUE == 0x00000002);
                if (uAccessMask & KEY_SET_VALUE) {
                    _tprintf(_T("        [    %04x] +    (KEY_SET_VALUE)\n"), KEY_SET_VALUE);
                }
                assert(KEY_CREATE_SUB_KEY == 0x00000004);
                if (uAccessMask & KEY_CREATE_SUB_KEY) {
                    _tprintf(_T("        [    %04x] +    (KEY_CREATE_SUB_KEY)\n"), KEY_CREATE_SUB_KEY);
                }
                assert(KEY_ENUMERATE_SUB_KEYS == 0x00000008);
                if (uAccessMask & KEY_ENUMERATE_SUB_KEYS) {
                    _tprintf(_T("        [    %04x] +    (KEY_ENUMERATE_SUB_KEYS)\n"), KEY_ENUMERATE_SUB_KEYS);
                }
                assert(KEY_NOTIFY == 0x00000010);
                if (uAccessMask & KEY_NOTIFY) {
                    _tprintf(_T("        [    %04x] +    (KEY_NOTIFY)\n"), KEY_NOTIFY);
                }
                assert(KEY_CREATE_LINK == 0x00000020);
                if (uAccessMask & KEY_NOTIFY) {
                    _tprintf(_T("        [    %04x] +    (KEY_CREATE_LINK)\n"), KEY_CREATE_LINK);
                }
                assert(KEY_WOW64_RES == 0x00000300);
                assert(KEY_WOW64_64KEY == 0x00000100);
                if ((uAccessMask & KEY_WOW64_RES) == KEY_WOW64_64KEY) {
                    _tprintf(_T("        [    %04x] +    (KEY_WOW64_64KEY)\n"), KEY_WOW64_64KEY);
                }
                assert(KEY_WOW64_32KEY == 0x00000200);
                if ((uAccessMask & KEY_WOW64_RES) == KEY_WOW64_32KEY) {
                    _tprintf(_T("        [    %04x] +    (KEY_WOW64_32KEY)\n"), KEY_WOW64_32KEY);
                }

                assert(ADS_RIGHT_DS_CREATE_CHILD == 0x00000001);
                if (uAccessMask & ADS_RIGHT_DS_CREATE_CHILD) {
                    _tprintf(_T("        [    %04x] + CC (ADS_RIGHT_DS_CREATE_CHILD)\n"), ADS_RIGHT_DS_CREATE_CHILD);
                }
                assert(ADS_RIGHT_DS_DELETE_CHILD == 0x00000002);
                if (uAccessMask & ADS_RIGHT_DS_DELETE_CHILD) {
                    _tprintf(_T("        [    %04x] + DC (ADS_RIGHT_DS_DELETE_CHILD)\n"), ADS_RIGHT_DS_DELETE_CHILD);
                }
                assert(ADS_RIGHT_ACTRL_DS_LIST == 0x00000004);
                if (uAccessMask & ADS_RIGHT_ACTRL_DS_LIST) {
                    _tprintf(_T("        [    %04x] + LC (ADS_RIGHT_ACTRL_DS_LIST (_CHILDREN))\n"),
                             ADS_RIGHT_ACTRL_DS_LIST);
                }
                assert(ADS_RIGHT_DS_SELF == 0x00000008);
                if (uAccessMask & ADS_RIGHT_DS_SELF) {
                    _tprintf(_T("        [    %04x] + SW (ADS_RIGHT_DS_SELF (_WRITE))\n"), ADS_RIGHT_DS_SELF);
                }
                assert(ADS_RIGHT_DS_READ_PROP == 0x00000010);
                if (uAccessMask & ADS_RIGHT_DS_READ_PROP) {
                    _tprintf(_T("        [    %04x] + RP (ADS_RIGHT_DS_READ_PROP)\n"), ADS_RIGHT_DS_READ_PROP);
                }
                assert(ADS_RIGHT_DS_WRITE_PROP == 0x00000020);
                if (uAccessMask & ADS_RIGHT_DS_WRITE_PROP) {
                    _tprintf(_T("        [    %04x] + WP (ADS_RIGHT_DS_WRITE_PROP)\n"), ADS_RIGHT_DS_WRITE_PROP);
                }
                assert(ADS_RIGHT_DS_DELETE_TREE == 0x00000040);
                if (uAccessMask & ADS_RIGHT_DS_DELETE_TREE) {
                    _tprintf(_T("        [    %04x] + DT (ADS_RIGHT_DS_DELETE_TREE)\n"), ADS_RIGHT_DS_DELETE_TREE);
                }
                assert(ADS_RIGHT_DS_LIST_OBJECT == 0x00000080);
                if (uAccessMask & ADS_RIGHT_DS_LIST_OBJECT) {
                    _tprintf(_T("        [    %04x] + LO (ADS_RIGHT_DS_LIST_OBJECT)\n"), ADS_RIGHT_DS_LIST_OBJECT);
                }
                assert(ADS_RIGHT_DS_CONTROL_ACCESS == 0x00000100);
                if (uAccessMask & ADS_RIGHT_DS_CONTROL_ACCESS) {
                    _tprintf(_T("        [    %04x] + CR (ADS_RIGHT_DS_CONTROL_ACCESS)\n"),
                             ADS_RIGHT_DS_CONTROL_ACCESS);
                }
            }

            if (!display_sid(_T("      ACE SID: "), (PSID)(upOffset + 8))) {
                return FALSE;
            }
        } else {
            /* Unknown format */
            _tprintf(_T("      Data:"));
            for (iData = 4; iData < pAceHeader->AceSize; iData++) {
                _tprintf(_T(" %02x"), ((PBYTE)upOffset)[iData]);
            }
            _tprintf(_T("\n"));
        }
        upOffset += pAceHeader->AceSize;
    }
    /* Ensure that all the structure has been covered */
    assert(upOffset == (UINT_PTR)pDacl + pDacl->AclSize);
    return TRUE;
}

/**
 * Display a Security Descriptor from a string representation
 */
static BOOL analyze_relative_security_desc(PSECURITY_DESCRIPTOR pSecDesc, ULONG ulSecDescSize)
{
    SECURITY_DESCRIPTOR_RELATIVE *pSecDescRel = NULL; /* PSECURITY_DESCRIPTOR is void*, not SECURITY_DESCRIPTOR_RELATIVE* */
    PACL pSacl, pDacl;

    if (ulSecDescSize != 0) {
        assert(ulSecDescSize >= sizeof(SECURITY_DESCRIPTOR_RELATIVE));
        _tprintf(_T("  SD size: %#lx\n"), ulSecDescSize);
    }
    assert(pSecDesc != NULL);
    assert(sizeof(SECURITY_DESCRIPTOR_RELATIVE) == 0x14);
    pSecDescRel = pSecDesc;

    if (pSecDescRel->Revision != SDDL_REVISION_1) {
        _tprintf(_T("  Revision (must be 1): %#x\n"), pSecDescRel->Revision);
        return FALSE;
    }
    if (pSecDescRel->Sbz1) { /* SBZ: Should Be Zero */
        _tprintf(_T("  Sbz1: %#x\n"), pSecDescRel->Sbz1);
    }
    /* Control bits are counted from high to low */
    _tprintf(_T("  Control: %#x\n"), pSecDescRel->Control);
    _tprintf(_T("    [15, %04x] %c OD (Owner Defaulted)\n"),
             SE_OWNER_DEFAULTED, (pSecDescRel->Control & SE_OWNER_DEFAULTED) ? '+' : '-');
    _tprintf(_T("    [14, %04x] %c GD (Group Defaulted)\n"),
             SE_GROUP_DEFAULTED, (pSecDescRel->Control & SE_GROUP_DEFAULTED) ? '+' : '-');
    _tprintf(_T("    [13, %04x] %c DP (DACL Present)\n"),
             SE_DACL_PRESENT, (pSecDescRel->Control & SE_DACL_PRESENT) ? '+' : '-');
    _tprintf(_T("    [12, %04x] %c DD (DACL Defaulted)\n"),
             SE_DACL_DEFAULTED, (pSecDescRel->Control & SE_DACL_DEFAULTED) ? '+' : '-');
    _tprintf(_T("    [11, %04x] %c SP (SACL Present)\n"),
             SE_SACL_PRESENT, (pSecDescRel->Control & SE_SACL_PRESENT) ? '+' : '-');
    _tprintf(_T("    [10, %04x] %c SD (SACL Defaulted)\n"),
             SE_SACL_DEFAULTED, (pSecDescRel->Control & SE_SACL_DEFAULTED) ? '+' : '-');
    _tprintf(_T("    [ 9, %04x] %c DT (DACL Trusted, does not require any editing of compound ACEs)\n"),
             0x40, (pSecDescRel->Control & 0x40) ? '+' : '-');
    _tprintf(_T("    [ 8, %04x] %c SS (Server Security)\n"),
             0x80, (pSecDescRel->Control & 0x80) ? '+' : '-');
    _tprintf(_T("    [ 7, %04x] %c DC (DACL Computed Inheritance Required)\n"),
             SE_DACL_AUTO_INHERIT_REQ, (pSecDescRel->Control & SE_DACL_AUTO_INHERIT_REQ) ? '+' : '-');
    _tprintf(_T("    [ 6, %04x] %c SC (SACL Computed Inheritance Required)\n"),
             SE_SACL_AUTO_INHERIT_REQ, (pSecDescRel->Control & SE_SACL_AUTO_INHERIT_REQ) ? '+' : '-');
    _tprintf(_T("    [ 5, %04x] %c DI/AI (DACL Auto-Inherited, created through inheritance)\n"),
             SE_DACL_AUTO_INHERITED, (pSecDescRel->Control & SE_DACL_AUTO_INHERITED) ? '+' : '-');
    _tprintf(_T("    [ 4, %04x] %c SI (SACL Auto-Inherited, created through inheritance)\n"),
             SE_SACL_AUTO_INHERITED, (pSecDescRel->Control & SE_SACL_AUTO_INHERITED) ? '+' : '-');
    _tprintf(_T("    [ 3, %04x] %c PD (DACL Protected from inherit operations)\n"),
             SE_DACL_PROTECTED, (pSecDescRel->Control & SE_DACL_PROTECTED) ? '+' : '-');
    _tprintf(_T("    [ 2, %04x] %c PS (SACL Protected from inherit operations)\n"),
             SE_SACL_PROTECTED, (pSecDescRel->Control & SE_SACL_PROTECTED) ? '+' : '-');
    _tprintf(_T("    [ 1, %04x] %c RM (Resource Manager Control Valid)\n"),
             SE_RM_CONTROL_VALID, (pSecDescRel->Control & SE_RM_CONTROL_VALID) ? '+' : '-');
    _tprintf(_T("    [ 0, %04x] %c SR (Self-Relative)\n"),
             SE_SELF_RELATIVE, (pSecDescRel->Control & SE_SELF_RELATIVE) ? '+' : '-');

    _tprintf(_T("  Owner offset: %#lx\n"), pSecDescRel->Owner);
    _tprintf(_T("  Group offset: %#lx\n"), pSecDescRel->Group);
    _tprintf(_T("  SACL offset: %#lx\n"), pSecDescRel->Sacl);
    _tprintf(_T("  DACL offset: %#lx\n"), pSecDescRel->Dacl);

    if (pSecDescRel->Owner) {
        assert(pSecDescRel->Owner >= 0x14);
        if (!display_sid(_T("  Owner: "), (PSID)((UINT_PTR)pSecDesc + pSecDescRel->Owner))) {
            return FALSE;
        }
    }

    if (pSecDescRel->Group) {
        assert(pSecDescRel->Group >= 0x14);
        if (!display_sid(_T("  Group: "), (PSID)((UINT_PTR)pSecDesc + pSecDescRel->Group))) {
            return FALSE;
        }
    }

    if (pSecDescRel->Control & SE_DACL_PRESENT) {
        assert(sizeof(ACL) == 8);
        assert(pSecDescRel->Dacl >= 0x14);
        assert(ulSecDescSize == 0 || pSecDescRel->Dacl + 8 <= ulSecDescSize);
        pDacl = (PACL)((UINT_PTR)pSecDesc + pSecDescRel->Dacl);
        _tprintf(_T("  DACL (Discretionary Access Control List):\n"));
        if (!analyze_acl(pDacl, (ulSecDescSize == 0) ? 0 : ((UINT_PTR)pSecDesc) + ulSecDescSize, 'D')) {
            return FALSE;
        }
    }

    if ((pSecDescRel->Control & SE_SACL_PRESENT) && pSecDescRel->Sacl != 0) {
        assert(sizeof(ACL) == 8);
        assert(pSecDescRel->Sacl >= 0x14);
        assert(ulSecDescSize == 0 || pSecDescRel->Sacl + 8 <= ulSecDescSize);
        pSacl = (PACL)((UINT_PTR)pSecDesc + pSecDescRel->Sacl);
        _tprintf(_T("  SACL (System Access Control List):\n"));
        if (!analyze_acl(pSacl, (ulSecDescSize == 0) ? 0 : ((UINT_PTR)pSecDesc) + ulSecDescSize, 'S')) {
            return FALSE;
        }
    }
    return TRUE;
}

/**
 * Display a Security Descriptor from a string representation
 * (SDDL = Security Descriptor Definition Language)
 */
static BOOL analyze_sddl(const TCHAR *pszSDDL)
{
    PSECURITY_DESCRIPTOR pSecDesc = NULL; /* PSECURITY_DESCRIPTOR is void* */
    ULONG ulSecDescSize = 0;
    BOOL fResult;

    _tprintf(_T("\"%s\":\n"), pszSDDL);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(pszSDDL, SDDL_REVISION_1, &pSecDesc, &ulSecDescSize)) {
        print_winerr(_T("ConvertStringSecurityDescriptorToSecurityDescriptor"));
        return FALSE;
    }
    assert(ulSecDescSize > 0);
    fResult = analyze_relative_security_desc(pSecDesc, ulSecDescSize);
    LocalFree(pSecDesc);
    return fResult;
}

/**
 * Enable or disable a privilege
 */
static BOOL change_privilege(LPCTSTR lpPrivilegeName, BOOL fEnable)
{
    LUID luid;
    HANDLE hToken;
    TOKEN_PRIVILEGES tpTokenPrivileges;

    if (!LookupPrivilegeValue(NULL, lpPrivilegeName, &luid)) {
        _ftprintf(stderr, _T("Error looking up privilege %s: "), lpPrivilegeName);
        print_winerr(_T("LookupPrivilegeValue"));
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        print_winerr(_T("OpenProcessToken"));
        return FALSE;
    }

    ZeroMemory(&tpTokenPrivileges, sizeof(TOKEN_PRIVILEGES));
    tpTokenPrivileges.PrivilegeCount = 1;
    tpTokenPrivileges.Privileges[0].Luid = luid;
    tpTokenPrivileges.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tpTokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        _ftprintf(stderr, _T("Error while %s privilege %s: "),
                  fEnable ? _T("enabling") : _T("disabling"), lpPrivilegeName);
        print_winerr(_T("AdjustTokenPrivileges"));
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

/**
 * Display the Security Descriptor of an object
 */
static BOOL analyze_named_object_security_desc(LPCTSTR pObjectName, SE_OBJECT_TYPE ObjectType)
{
    DWORD dwStatus;
    PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
    LPTSTR pszStringSecDesc = NULL;
    BOOL fResult;

    /* Old versions of MinGW didn't use a constant string
     * (for example mingw-w64-dev 2.0.1-1 on Ubuntu 12.04)
     */
    LPTSTR pNonConstObjectName = (LPTSTR)pObjectName;

    _tprintf(_T("Security Descriptor of \"%s\":\n"), pObjectName);

    /* Try enabling SeBackupPrivilege, if possible */
    change_privilege(SE_BACKUP_NAME, TRUE);
    /* Try enabling SeSecurityPrivilege, if possible */
    change_privilege(SE_SECURITY_NAME, TRUE);
    dwStatus = GetNamedSecurityInfo(
        pNonConstObjectName, ObjectType, BACKUP_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &pSecurityDescriptor);

    if (dwStatus == ERROR_SUCCESS) {
        /* This is rare enough to be reported */
        _tprintf(_T("... GetNamedSecurityInfo(BACKUP_SECURITY_INFORMATION) succeeded :)\n"));
    } else if (dwStatus == ERROR_ACCESS_DENIED) {
        /* Retry with lower desired access, but with SACL */
        dwStatus = GetNamedSecurityInfo(
            pNonConstObjectName, ObjectType,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION |
            SCOPE_SECURITY_INFORMATION |
            PROTECTED_DACL_SECURITY_INFORMATION |
            PROTECTED_SACL_SECURITY_INFORMATION |
            UNPROTECTED_DACL_SECURITY_INFORMATION |
            UNPROTECTED_SACL_SECURITY_INFORMATION,
            NULL, NULL, NULL, NULL, &pSecurityDescriptor);
        if (dwStatus == ERROR_PRIVILEGE_NOT_HELD || dwStatus == ERROR_ACCESS_DENIED) {
            /* Querying SACL requires SeSecurityPrivilege. Retry without SACL */
            _tprintf(_T("... not enough privilege for GetNamedSecurityInfo, retrying without SACL\n"));
            dwStatus = GetNamedSecurityInfo(
                pNonConstObjectName, ObjectType,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION |
                LABEL_SECURITY_INFORMATION |
                SCOPE_SECURITY_INFORMATION |
                PROTECTED_DACL_SECURITY_INFORMATION |
                UNPROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, NULL, NULL, &pSecurityDescriptor);
        }
    }
    /* Disable privileges that have been enabled */
    change_privilege(SE_SECURITY_NAME, FALSE);
    change_privilege(SE_BACKUP_NAME, FALSE);
    if (dwStatus != ERROR_SUCCESS) {
        SetLastError(dwStatus);
        print_winerr(_T("GetNamedSecurityInfo"));
        return FALSE;
    }

    if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
            pSecurityDescriptor, SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION |
            SCOPE_SECURITY_INFORMATION |
            PROTECTED_DACL_SECURITY_INFORMATION |
            PROTECTED_SACL_SECURITY_INFORMATION |
            UNPROTECTED_DACL_SECURITY_INFORMATION |
            UNPROTECTED_SACL_SECURITY_INFORMATION,
            &pszStringSecDesc, NULL)) {
        print_winerr(_T("ConvertSecurityDescriptorToStringSecurityDescriptor"));
        LocalFree(pSecurityDescriptor);
        return FALSE;
    }
    assert(pszStringSecDesc != NULL);
    if (*pszStringSecDesc == 0) {
        _tprintf(_T("  empty SDDL\n"));
    } else {
        _tprintf(_T("  SDDL: %s\n"), pszStringSecDesc);
    }
    LocalFree(pszStringSecDesc);

    fResult = analyze_relative_security_desc(pSecurityDescriptor, 0);
    LocalFree(pSecurityDescriptor);
    return fResult;
}

int _tmain(int argc, TCHAR **argv)
{
    int i;

    /* Analyze the security descriptors given on the command line */
    if (argc >= 2) {
        for (i = 1; i < argc; i++) {
            if (i != 1) {
                _tprintf(_T("\n"));
            }
            if (i + 1 < argc && (!_tcscmp(argv[i], _T("-f")) || !_tcscmp(argv[i], _T("--file")))) {
                /* Analyze a file */
                if (!analyze_named_object_security_desc(argv[++i], SE_FILE_OBJECT)) {
                    return 1;
                }
                continue;
            }
            if (i + 1 < argc && (!_tcscmp(argv[i], _T("-r")) || !_tcscmp(argv[i], _T("--reg")))) {
                /* Analyze a registry key */
                if (!analyze_named_object_security_desc(argv[++i], SE_REGISTRY_KEY)) {
                    return 1;
                }
                continue;
            }
            if (i + 1 < argc && !_tcscmp(argv[i], _T("--obj"))) {
                /* Analyze a kernel object such as a semaphore, event, mutex, waitable timer and file mapping */
                if (!analyze_named_object_security_desc(argv[++i], SE_KERNEL_OBJECT)) {
                    return 1;
                }
                continue;
            }
            if (!analyze_sddl(argv[i])) {
                return 1;
            }
        }
        return 0;
    }

    /* Analyze some security descriptors, if none are provided */
    for (i = 0; i < (int)ARRAYSIZE(g_example_security_descriptors); i++) {
        if (i != 0) {
            _tprintf(_T("\n"));
        }
        if (!analyze_sddl(g_example_security_descriptors[i])) {
            /* Old versions of Wine (for example 1.6.2 on Debian 8) do not
             * support Mandatory Label such as "S:(ML;;NW;;;LW)":
             *     ConvertStringSecurityDescriptorToSecurityDescriptor: error 1705, Invalid string UUID
             */
            if (GetLastError() == RPC_S_INVALID_STRING_UUID && _tcsstr(g_example_security_descriptors[i], _T("S:"))) {
                _tprintf(_T("Ignoring error...\n"));
                continue;
            }
            return 1;
        }
    }

    /* Analyze the security descriptors of some objects */
    _tprintf(_T("\n"));
    if (!analyze_named_object_security_desc(_T("C:"), SE_FILE_OBJECT)) {
        return 1;
    }
    _tprintf(_T("\n"));
    if (!analyze_named_object_security_desc(
            _T("MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion"), SE_REGISTRY_KEY)) {
        return 1;
    }
    _tprintf(_T("\n"));
    if (!analyze_named_object_security_desc(_T("CURRENT_USER\\Environment"), SE_REGISTRY_KEY)) {
        return 1;
    }
    return 0;
}
