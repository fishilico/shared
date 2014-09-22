/**
 * Show stats available through "netstat" command with Windows API.
 *
 * Doc:
 * * structures in iprtrmib.h
*/
#include <winsock2.h>
#include "common.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>

/* Describe an enum with a switch-case structure */
#define case_print(value, text) case value: _tprintf(text); break

/* Define a specific macro because the last parameter of Get*Table is a boolean
 * Which indicates whether the output is sorted */
#define _TableBufSizeToAlloc(f, tabletype) \
    static tabletype* f##_a(void) \
    { \
        tabletype* pTable = NULL; \
        DWORD dwSize = 0, dwRet; \
        dwRet = f(NULL, &dwSize, FALSE); \
        while (dwRet == ERROR_INSUFFICIENT_BUFFER) { \
            if (pTable) { \
                HeapFree(GetProcessHeap(), 0, pTable); \
            } \
            pTable = HeapAlloc(GetProcessHeap(), 0, dwSize); \
            if (!pTable) { \
                print_winerr(_T("HeapAlloc")); \
                return NULL; \
            } \
            /* Set bSort parameter to TRUE */ \
            dwRet = f(pTable, &dwSize, TRUE); \
        } \
        if (dwRet != NO_ERROR || !pTable) { \
            SetLastError(dwRet); \
            print_winerr(_T(#f)); \
            return NULL; \
        } \
        return pTable; \
    }

_TableBufSizeToAlloc(GetIfTable, MIB_IFTABLE)
_TableBufSizeToAlloc(GetIpAddrTable, MIB_IPADDRTABLE)
_TableBufSizeToAlloc(GetIpForwardTable, MIB_IPFORWARDTABLE)
_TableBufSizeToAlloc(GetTcpTable, MIB_TCPTABLE)
_TableBufSizeToAlloc(GetUdpTable, MIB_UDPTABLE)

/**
 * Declare our own InetNtop if not available (< Vista)
 */
#ifndef InetNtop
#    define InetNtop _InetNtop
static LPCTSTR InetNtop(INT Family, const void *pAddr, LPTSTR pStringBuf, size_t StringBufSize)
{
    assert(pAddr);
    assert(pStringBuf);
    if (Family == AF_INET) {
        const BYTE *pbAddr = (PBYTE)pAddr;
        assert(StringBufSize >= 16);
        _sntprintf(pStringBuf, StringBufSize, _T("%u.%u.%u.%u"),
                   pbAddr[0], pbAddr[1], pbAddr[2], pbAddr[3]);
    } else if (Family == AF_INET6) {
        const WORD *pwAddr = (PWORD)pAddr;
        assert(StringBufSize >= 46);
        _sntprintf(pStringBuf, StringBufSize, _T("%4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x"),
                   pwAddr[0], pwAddr[1], pwAddr[2], pwAddr[3],
                   pwAddr[4], pwAddr[5], pwAddr[6], pwAddr[7]);
    } else {
        assert(FALSE);
    }
    return pStringBuf;
}
#endif

/**
 * Use GetIfTable
 */
static void dump_if_table(void)
{
    MIB_IFTABLE *pIfTable;
    const MIB_IFROW *pIfRow;
    DWORD i, j;

    pIfTable = GetIfTable_a();
    if (!pIfTable) {
        return;
    }
    _tprintf(_T("Interfaces (%lu):\n"), pIfTable->dwNumEntries);
    for (i = 0; i < pIfTable->dwNumEntries; i++) {
        pIfRow = &pIfTable->table[i];
        _tprintf(_T("  #%lu: %." STR(MAX_INTERFACE_NAME_LEN) PRIsW "\n"),
                 pIfRow->dwIndex, pIfRow->wszName);
        _tprintf(_T("    * Type: "));
        switch (pIfRow->dwType) {
            case_print(IF_TYPE_OTHER, _T("Other"));
            case_print(IF_TYPE_ETHERNET_CSMACD, _T("Ethernet"));
            case_print(IF_TYPE_ISO88025_TOKENRING, _T("Token Ring"));
            case_print(IF_TYPE_PPP, _T("PPP"));
            case_print(IF_TYPE_SOFTWARE_LOOPBACK, _T("Software Lookback"));
            case_print(IF_TYPE_ATM, _T("ATM"));
            case_print(IF_TYPE_IEEE80211, _T("IEEE 802.11 Wireless"));
            case_print(IF_TYPE_TUNNEL, _T("Tunnel type encapsulation"));
            case_print(IF_TYPE_IEEE1394, _T("IEEE 1394 Firewire"));
            default:
                _tprintf(_T("Unknown (%lu)"), pIfRow->dwType);
                break;
        }
        _tprintf(_T("\n"));
        _tprintf(_T("    * Mtu: %lu\n"), pIfRow->dwMtu);
        _tprintf(_T("    * Speed: %lu\n"), pIfRow->dwSpeed);
        _tprintf(_T("    * Physical addr: "));
        for (j = 0; j < pIfRow->dwPhysAddrLen; j++) {
            if (j) {
                _tprintf(_T("-"));
            }
            printf("%.2X", pIfRow->bPhysAddr[j]);
        }
        if (!j) {
            _tprintf(_T("None"));
        }
        _tprintf(_T("\n"));
        _tprintf(_T("    * Admin Status: %lu\n"), pIfRow->dwAdminStatus);
        _tprintf(_T("    * Oper Status: "));
        switch (pIfRow->dwOperStatus) {
            case_print(IF_OPER_STATUS_NON_OPERATIONAL, _T("Non Operational"));
            case_print(IF_OPER_STATUS_UNREACHABLE, _T("Unreachable"));
            case_print(IF_OPER_STATUS_DISCONNECTED, _T("Disconnected"));
            case_print(IF_OPER_STATUS_CONNECTING, _T("Connecting"));
            case_print(IF_OPER_STATUS_CONNECTED, _T("Connected"));
            case_print(IF_OPER_STATUS_OPERATIONAL, _T("Operational"));
            default:
                _tprintf(_T("Unknown (%lu)"), pIfRow->dwOperStatus);
                break;
        }
        _tprintf(_T("\n"));
        _tprintf(_T("    * Description: "));
        for (j = 0; j < pIfRow->dwDescrLen && j < MAXLEN_IFDESCR; j++) {
            _tprintf(_T("%c"), pIfRow->bDescr[j]);
        }
        _tprintf(_T("\n"));
    }
    HeapFree(GetProcessHeap(), 0, pIfTable);
}

/**
 * Use GetIpAddrTable
 */
static void dump_ipv4addr_table(void)
{
    MIB_IPADDRTABLE *pIpAddrTable;
    const MIB_IPADDRROW *pIpAddrRow;
    DWORD i;
    TCHAR szAddrBuffer[16], szMaskBuffer[16], szBCastBuffer[16];

    pIpAddrTable = GetIpAddrTable_a();
    if (!pIpAddrTable) {
        return;
    }
    _tprintf(_T("IPv4 addresses (%lu):\n"), pIpAddrTable->dwNumEntries);
    for (i = 0; i < pIpAddrTable->dwNumEntries; i++) {
        pIpAddrRow = &pIpAddrTable->table[i];
        _tprintf(_T("  * Iface %lu: %s/%s\n"),
                 pIpAddrRow->dwIndex,
                 InetNtop(AF_INET, &pIpAddrRow->dwAddr, szAddrBuffer, ARRAYSIZE(szAddrBuffer)),
                 InetNtop(AF_INET, &pIpAddrRow->dwMask, szMaskBuffer, ARRAYSIZE(szMaskBuffer)));
        _tprintf(_T("    * Broadcast: %s\n"),
                 InetNtop(AF_INET, &pIpAddrRow->dwBCastAddr, szBCastBuffer, ARRAYSIZE(szBCastBuffer)));
        _tprintf(_T("    * Reassembly size: %lu\n"), pIpAddrRow->dwReasmSize);
    }
    HeapFree(GetProcessHeap(), 0, pIpAddrTable);
}

/**
 * Use GetIpForwardTable
 */
static void dump_ipv4fwd_table(void)
{
    MIB_IPFORWARDTABLE *pIpForwardTable;
    const MIB_IPFORWARDROW *pIpForwardRow;
    DWORD i;
    TCHAR szDestBuffer[16], szMaskBuffer[16], szNextHopBuffer[16];

    pIpForwardTable = GetIpForwardTable_a();
    if (!pIpForwardTable) {
        return;
    }
    _tprintf(_T("IPv4 routes (%lu):\n"), pIpForwardTable->dwNumEntries);
    for (i = 0; i < pIpForwardTable->dwNumEntries; i++) {
        pIpForwardRow = &pIpForwardTable->table[i];
        _tprintf(_T("  * Iface %lu: %s/%s\n"),
                 pIpForwardRow->dwForwardIfIndex,
                 InetNtop(AF_INET, &pIpForwardRow->dwForwardDest, szDestBuffer, ARRAYSIZE(szDestBuffer)),
                 InetNtop(AF_INET, &pIpForwardRow->dwForwardMask, szMaskBuffer, ARRAYSIZE(szMaskBuffer)));
        _tprintf(_T("    * Next Hop: %s\n"),
                 InetNtop(AF_INET, &pIpForwardRow->dwForwardNextHop, szNextHopBuffer, ARRAYSIZE(szNextHopBuffer)));
        _tprintf(_T("    * Type: "));
/* Old MinGW headers do not define MIB_IPROUTE_* */
#ifdef MIB_IPROUTE_TYPE_OTHER
        switch (pIpForwardRow->dwForwardType) {
            case_print(MIB_IPROUTE_TYPE_OTHER, _T("Other"));
            case_print(MIB_IPROUTE_TYPE_INVALID, _T("Invalid"));
            case_print(MIB_IPROUTE_TYPE_DIRECT, _T("Direct"));
            case_print(MIB_IPROUTE_TYPE_INDIRECT, _T("Indirect"));
            default:
                _tprintf(_T("Unknown (%lu)"), pIpForwardRow->dwForwardType);
                break;
        }
#else
        _tprintf(_T("%lu"), pIpForwardRow->dwForwardType);
#endif
        _tprintf(_T("\n"));
        _tprintf(_T("    * Proto: "));
/* Old MinGW headers do not define MIB_IPPROTO_* */
#ifdef MIB_IPPROTO_OTHER
        switch (pIpForwardRow->dwForwardProto) {
            case_print(MIB_IPPROTO_OTHER, _T("Other"));
            case_print(MIB_IPPROTO_LOCAL, _T("Local"));
            case_print(MIB_IPPROTO_NETMGMT, _T("Static (Network Management)"));
            case_print(MIB_IPPROTO_ICMP, _T("ICMP redirect"));
            case_print(MIB_IPPROTO_EGP, _T("Exterior Gateway Protocol (EGP)"));
            case_print(MIB_IPPROTO_GGP, _T("Gateway-to-Gateway Protocol (GGP)"));
            case_print(MIB_IPPROTO_HELLO, _T("Hello Protocol"));
            case_print(MIB_IPPROTO_RIP, _T("Routing Information Protocol (RIP)"));
            case_print(MIB_IPPROTO_IS_IS, _T("Intermediate System-to-Intermediate System (IS-IS)"));
            case_print(MIB_IPPROTO_ES_IS, _T("End System-to-Intermediate System (ES-IS)"));
            case_print(MIB_IPPROTO_CISCO, _T("Cisco Interior Gateway Routing Protocol (IGRP)"));
            case_print(MIB_IPPROTO_BBN, _T("BBN Internet Gateway Protocol (IGP) using SPF"));
            case_print(MIB_IPPROTO_OSPF, _T("Open Shortest Path First (OSPF)"));
            case_print(MIB_IPPROTO_BGP, _T("Border Gateway Protocol (BGP)"));
            case_print(MIB_IPPROTO_NT_AUTOSTATIC, _T("special Windows auto static route"));
            case_print(MIB_IPPROTO_NT_STATIC, _T("special Windows static route"));
            case_print(MIB_IPPROTO_NT_STATIC_NON_DOD, _T("special Windows static route not based on Internet standards"));
            default:
                _tprintf(_T("Unknown (%lu)"), pIpForwardRow->dwForwardProto);
                break;
        }
#else
        _tprintf(_T("%lu"), pIpForwardRow->dwForwardProto);
#endif
        _tprintf(_T("\n"));
        _tprintf(_T("    * Age: %lu\n"), pIpForwardRow->dwForwardAge);
        _tprintf(_T("    * Metric1: %lu\n"), pIpForwardRow->dwForwardMetric1);
    }
    HeapFree(GetProcessHeap(), 0, pIpForwardTable);
}

/**
 * Use GetTcpTable
 */
static void dump_tcp4_table(void)
{
    MIB_TCPTABLE *pTcpTable;
    const MIB_TCPROW *pTcpRow;
    DWORD i;
    TCHAR szLocalAddrBuffer[16], szRemoteAddrBuffer[16];

    pTcpTable = GetTcpTable_a();
    if (!pTcpTable) {
        return;
    }
    _tprintf(_T("TCP/IPv4 connections (%lu):\n"), pTcpTable->dwNumEntries);
    for (i = 0; i < pTcpTable->dwNumEntries; i++) {
        pTcpRow = &pTcpTable->table[i];
        _tprintf(_T("  * %s/%lu -> %s/%lu ("),
                 InetNtop(AF_INET, &pTcpRow->dwLocalAddr, szLocalAddrBuffer, ARRAYSIZE(szLocalAddrBuffer)),
                 ntohs((WORD)pTcpRow->dwLocalPort),
                 InetNtop(AF_INET, &pTcpRow->dwRemoteAddr, szRemoteAddrBuffer, ARRAYSIZE(szRemoteAddrBuffer)),
                 ntohs((WORD)pTcpRow->dwRemotePort));
        switch (pTcpRow->dwState) {
            case_print(MIB_TCP_STATE_CLOSED, _T("CLOSED"));
            case_print(MIB_TCP_STATE_LISTEN, _T("LISTEN"));
            case_print(MIB_TCP_STATE_SYN_SENT, _T("SYN SENT"));
            case_print(MIB_TCP_STATE_SYN_RCVD, _T("SYN RECEIVED"));
            case_print(MIB_TCP_STATE_ESTAB, _T("ESTABLISHED"));
            case_print(MIB_TCP_STATE_FIN_WAIT1, _T("FIN WAIT 1"));
            case_print(MIB_TCP_STATE_FIN_WAIT2, _T("FIN WAIT 2"));
            case_print(MIB_TCP_STATE_CLOSE_WAIT, _T("CLOSE WAIT"));
            case_print(MIB_TCP_STATE_CLOSING, _T("CLOSING"));
            case_print(MIB_TCP_STATE_LAST_ACK, _T("LAST ACK"));
            case_print(MIB_TCP_STATE_TIME_WAIT, _T("TIME WAIT"));
            case_print(MIB_TCP_STATE_DELETE_TCB, _T("DELETE TCB"));
            default:
                _tprintf(_T("Unknown state %lu"), pTcpRow->dwState);
                break;
        }
        _tprintf(_T(")\n"));
    }
    HeapFree(GetProcessHeap(), 0, pTcpTable);
}

/**
 * Use GetUdpTable
 */
static void dump_udp4_table(void)
{
    MIB_UDPTABLE *pUdpTable;
    const MIB_UDPROW *pUdpRow;
    DWORD i;
    TCHAR szLocalAddrBuffer[16];

    pUdpTable = GetUdpTable_a();
    if (!pUdpTable) {
        return;
    }
    _tprintf(_T("UDP/IPv4 connections (%lu):\n"), pUdpTable->dwNumEntries);
    for (i = 0; i < pUdpTable->dwNumEntries; i++) {
        pUdpRow = &pUdpTable->table[i];
        _tprintf(_T("  * %s/%lu\n"),
                 InetNtop(AF_INET, &pUdpRow->dwLocalAddr, szLocalAddrBuffer, ARRAYSIZE(szLocalAddrBuffer)),
                 ntohs((WORD)pUdpRow->dwLocalPort));
    }
    HeapFree(GetProcessHeap(), 0, pUdpTable);
}

int _tmain()
{
    dump_if_table();
    _tprintf(_T("\n"));
    dump_ipv4addr_table();
    _tprintf(_T("\n"));
    dump_ipv4fwd_table();
    _tprintf(_T("\n"));
    dump_tcp4_table();
    _tprintf(_T("\n"));
    dump_udp4_table();
    return 0;
}
