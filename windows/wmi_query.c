/**
 * Query some information to the local WMI service
 *
 * Documentation:
 * In VisualBasic, WMI can be used like this, for example to enumerate local USB drives:
 *     Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
 *     Set colItems = objWMIService.ExecQuery("Select * from Win32_DiskDrive WHERE InterfaceType='USB'",,48)
 *     For Each drive In colItems
 *         If drive.mediaType <> "" Then
 *             MsgBox "USB drive at " & drive.DeviceId
 *         End If
 *     Next
 *
 * Links:
 * * https://msdn.microsoft.com/en-us/library/aa390418(v=vs.85).aspx
 *   Example: Creating a WMI Application
 * * https://msdn.microsoft.com/en-us/library/aa391769(v=vs.85).aspx
 *   IWbemLocator::ConnectServer method
 * * https://github.com/wine-mirror/wine/blob/master/dlls/wbemprox/tests/query.c
 *   Wine wbemprox.dll query testsuite
 */
#define COBJMACROS

#include "common.h"
#include <inttypes.h>
#include <wbemidl.h>

/* Redefine some GUID locally, to avoid having to link to wbemuuid */
static const GUID my_CLSID_WbemLocator =
    { 0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24} };
static const GUID my_IID_IWbemLocator =
    { 0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24} };

/**
 * Run a query and returns an enumerator on the result
 */
static IEnumWbemClassObject *wmi_query_enumerate(IWbemServices *pSvc, const OLECHAR *strQuery)
{
    HRESULT hRes;
    IEnumWbemClassObject *pEnumerator = NULL;
    BSTR strWQL, strNonConstQuery;

    strWQL = SysAllocString(OLESTR("WQL"));
    strNonConstQuery = SysAllocString(strQuery);
    assert(strWQL != NULL && strNonConstQuery != NULL);
    hRes = IWbemServices_ExecQuery(
        pSvc, /* This */
        strWQL, /* BSTR strQueryLanguage */
        strNonConstQuery, /* BSTR strQuery */
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, /* LONG lFlags */
        NULL, /* IWbemContext *pCtx */
        &pEnumerator); /* IEnumWbemClassObject **ppEnum */
    SysFreeString(strWQL);
    SysFreeString(strNonConstQuery);
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: IWbemServices::ExecQuery returned %#lx\n"), hRes);
        return NULL;
    }
    assert(pEnumerator != NULL);
    return pEnumerator;
}

/**
 * Get the next object in a WMI enumeration, or NULL at the end
 */
static IWbemClassObject *wmi_enum_nextobj(IEnumWbemClassObject *pEnumerator)
{
    HRESULT hRes;
    IWbemClassObject *pclsObj = NULL;
    ULONG ulReturn = 0;

    hRes = IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &ulReturn);
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: IEnumWbemClassObject::Next returned %#lx\n"), hRes);
        return NULL;
    }
    if (!ulReturn) {
        return NULL;
    }
    assert(pclsObj != NULL);
    return pclsObj;
}

/**
 * Print the content of a VARIANT knowing its type
 */
static void print_variant(CIMTYPE vtType, const VARIANT *pvt)
{
    switch (vtType) {
        case CIM_EMPTY:
            _tprintf(_T("(empty)"));
            break;
        case CIM_SINT8:
            _tprintf(_T("%" PRId8), pvt->bVal);
            break;
        case CIM_UINT8:
            _tprintf(_T("%" PRIu8), pvt->bVal);
            break;
        case CIM_SINT16:
            _tprintf(_T("%" PRId16), pvt->iVal);
            break;
        case CIM_UINT16:
            _tprintf(_T("%" PRIu16), pvt->iVal);
            break;
        case CIM_SINT32:
            _tprintf(_T("%" PRId32), pvt->intVal);
            break;
        case CIM_UINT32:
            _tprintf(_T("%" PRIu32), pvt->uintVal);
            break;
        case CIM_SINT64:
            _tprintf(_T("%" PRId64), pvt->llVal);
            break;
        case CIM_UINT64:
            _tprintf(_T("%" PRIu64), pvt->llVal);
            break;
        case CIM_REAL32:
            _tprintf(_T("%f"), pvt->fltVal);
            break;
        case CIM_REAL64:
            _tprintf(_T("%g"), pvt->dblVal);
            break;
        case CIM_BOOLEAN:
            _tprintf(_T("%s"), pvt->boolVal ? _T("TRUE") : _T("FALSE"));
            break;
        case CIM_STRING:
            _tprintf(_T("%" PRIsOLE), pvt->bstrVal);
            break;
        case CIM_DATETIME:
            _tprintf(_T("<DateTime>"));
            break;
        case CIM_REFERENCE:
            _tprintf(_T("<Reference>"));
            break;
        case CIM_CHAR16:
            _tprintf(_T("<Char16>"));
            break;
        case CIM_OBJECT:
            _tprintf(_T("<Object>"));
            break;
        default:
            if (vtType & CIM_FLAG_ARRAY) {
                /* FIXME: how to read item count from VARIANT *pvt? */
                _tprintf(_T("<Array>"));
            } else {
                _tprintf(_T("Unknown type %lu"), vtType);
            }
            break;
    }
}

/**
 * Show all the properties of an object
 */
static void dump_object_properties(IWbemClassObject *pclsObj, LPCTSTR szLinePrefix)
{
    HRESULT hRes;
    BSTR strName;
    VARIANT vtProp;
    CIMTYPE vtType;

    hRes = IWbemClassObject_BeginEnumeration(pclsObj, 0);
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: IWbemClassObject::BeginEnumeration returned %#lx\n"), hRes);
        return;
    }
    for (;;) {
        hRes = IWbemClassObject_Next(pclsObj, 0, &strName, &vtProp, &vtType, NULL);
        if (hRes == WBEM_S_NO_MORE_DATA) {
            break;
        } else if (FAILED(hRes)) {
            _ftprintf(stderr, _T("Error: IWbemClassObject::Next returned %#lx\n"), hRes);
            break;
        }
        assert(strName != NULL);

        _tprintf(_T("%s%" PRIsOLE " = "), szLinePrefix, strName);
        print_variant(vtType, &vtProp);
        _tprintf(_T("\n"));

        SysFreeString(strName);
        VariantClear(&vtProp);
    }
    IWbemClassObject_EndEnumeration(pclsObj);
}

/**
 * Dump information about running proccesses
 *
 * Example of outputed item with wine:
 *     - Process "services.exe":
 *       * Caption = services.exe
 *       * CommandLine = services.exe
 *       * Description = services.exe
 *       * Handle = 14
 *       * Name = services.exe
  *      * ParentProcessID = 10
 *       * ProcessID = 14
 *       * ThreadCount = 7
 *       * WorkingSetSize = 179044
*/
static BOOL dump_running_processes(IWbemServices *pSvc)
{
    HRESULT hRes;
    IEnumWbemClassObject *pEnumerator;
    IWbemClassObject *pclsObj;
    VARIANT vtProp;
    CIMTYPE vtType;

    pEnumerator = wmi_query_enumerate(pSvc, OLESTR("SELECT * FROM Win32_Process"));
    if (!pEnumerator) {
        return FALSE;
    }
    _tprintf(_T("Processes:\n"));
    while ((pclsObj = wmi_enum_nextobj(pEnumerator)) != NULL) {
        /* Get process name */
        hRes = IWbemClassObject_Get(pclsObj, OLESTR("Name"), 0, &vtProp, &vtType, 0);
        if (FAILED(hRes)) {
            _ftprintf(stderr, _T("Error: IWbemClassObject::Get returned %#lx\n"), hRes);
            IWbemClassObject_Release(pclsObj);
            continue;
        }
        _tprintf(_T("   - Process \""));
        print_variant(vtType, &vtProp);
        _tprintf(_T("\":\n"));
        VariantClear(&vtProp);

        /* Enumerate object properties */
        dump_object_properties(pclsObj, _T("      * "));
        IWbemClassObject_Release(pclsObj);
    }
    IEnumWbemClassObject_Release(pEnumerator);
    return TRUE;
}

/**
 * Dump information about disk drives
 *
 * Example of output with wine:
 *     Disk drives:
 *        - Drive:
 *           * DeviceId = \\\\.\\PHYSICALDRIVE0
 *           * Index = 0
 *           * InterfaceType = IDE
 *           * Manufacturer = (Standard disk drives)
 *           * MediaType = Fixed hard disk
 *           * Model = Wine Disk Drive
 *           * PNPDeviceID = IDE\Disk\VEN_WINE
 *           * SerialNumber = WINEHDISK
 *           * Size = 420000
 */
static BOOL dump_disk_drives(IWbemServices *pSvc)
{
    IEnumWbemClassObject *pEnumerator;
    IWbemClassObject *pclsObj;

    pEnumerator = wmi_query_enumerate(pSvc, OLESTR("SELECT * FROM Win32_DiskDrive"));
    if (!pEnumerator) {
        return FALSE;
    }
    _tprintf(_T("Disk drives:\n"));
    while ((pclsObj = wmi_enum_nextobj(pEnumerator)) != NULL) {
        _tprintf(_T("   - Drive:\n"));
        dump_object_properties(pclsObj, _T("      * "));
        IEnumWbemClassObject_Release(pclsObj);
    }
    IEnumWbemClassObject_Release(pEnumerator);
    return TRUE;
}

/**
 * Dump information about logical disks
 *
 * Example of output with wine:
 *     Logical disks:
 *        - Disk:
 *           * DeviceId = C:
 *           * DriveType = 3
 *           * FileSystem = NTFS
 *           * FreeSpace = 228884
 *           * Name = C:
 *           * Size = 228884
 *           * VolumeName =
 *           * VolumeSerialNumber = 00000000
 */
static BOOL dump_logical_disks(IWbemServices *pSvc)
{
    IEnumWbemClassObject *pEnumerator;
    IWbemClassObject *pclsObj;

    pEnumerator = wmi_query_enumerate(pSvc, OLESTR("SELECT * FROM Win32_LogicalDisk"));
    if (!pEnumerator) {
        return FALSE;
    }
    _tprintf(_T("Logical disks:\n"));
    while ((pclsObj = wmi_enum_nextobj(pEnumerator)) != NULL) {
        _tprintf(_T("   - Disk:\n"));
        dump_object_properties(pclsObj, _T("      * "));
        IEnumWbemClassObject_Release(pclsObj);
    }
    IEnumWbemClassObject_Release(pEnumerator);
    return TRUE;
}

int _tmain(void)
{
    HRESULT hRes;
    BOOL bRes = TRUE;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    BSTR strRootCIMV2;

    /* Initialize the COM library */
    hRes = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: CoInitializeEx returned %#lx\n"), hRes);
        return 1;
    }

    /* Register security */
    hRes = CoInitializeSecurity(
        NULL, /* PSECURITY_DESCRIPTOR pSecDesc */
        -1, /* LONG cAuthSvc */
        NULL, /* SOLE_AUTHENTICATION_SERVICE *asAuthSvc */
        NULL, /* reserved */
        RPC_C_AUTHN_LEVEL_DEFAULT, /* DWORD dwAuthnLevel */
        RPC_C_IMP_LEVEL_IMPERSONATE, /* DWORD dwImpLevel */
        NULL, /* void *pAuthList */
        EOAC_NONE, /* DWORD dwCapabilities */
        NULL); /* reserved */
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: CoInitializeSecurity returned %#lx\n"), hRes);
        goto cleanup;
    }

    /* Get a locator to Windows Management */
    hRes = CoCreateInstance(
        &my_CLSID_WbemLocator, /* REFCLSID rclsid */
        NULL, /* LPUNKNOWN pUnkOuter */
        CLSCTX_INPROC_SERVER, /* DWORD dwClsContext */
        &my_IID_IWbemLocator, /* REFIID riid, */
        (LPVOID *)&pLoc); /* PVOID *ppv */
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: CoCreateInstance(WbemLocator) returned %#lx\n"), hRes);
        goto cleanup;
    }
    assert(pLoc != NULL);

    /* Connect to Windows Management with the current user */
    strRootCIMV2 = SysAllocString(OLESTR("ROOT\\CIMV2"));
    assert(strRootCIMV2 != NULL);
    hRes = IWbemLocator_ConnectServer(
        pLoc, /* This */
        strRootCIMV2, /* BSTR strNetworkResource */
        NULL, /* BSTR strUser */
        NULL, /* BSTR strPassword */
        NULL, /* BSTR strLocale */
        0, /* LONG lSecurityFlags */
        NULL, /* BSTR strAuthority */
        NULL, /* IWbemContext *pCtx */
        &pSvc); /* IWbemServices **ppNamespace */
    SysFreeString(strRootCIMV2);
    if (FAILED(hRes)) {
        if (hRes == (HRESULT)WBEM_E_FAILED) {
            /* WMI is not supported, for example on old Wine.
             * Ignore such a runtime failure.
             */
            _tprintf(_T("Failed to connect to Windows Management Interface, exiting.\n"));
            hRes = WBEM_S_NO_ERROR;
            goto cleanup;
        }
        _ftprintf(stderr, _T("Error: IWbemLocator::ConnectServer returned %#lx\n"), hRes);
        goto cleanup;
    }
    assert(pSvc != NULL);

    /* Set the authentication information used to make calls on IWbemServices */
    hRes = CoSetProxyBlanket(
        (IUnknown *)pSvc, /* IUnknown *pProxy */
        RPC_C_AUTHN_WINNT, /* DWORD dwAuthnSvc */
        RPC_C_AUTHZ_NONE, /* DWORD dwAuthzSvc */
        NULL, /* OLECHAR *pServerPrincName */
        RPC_C_AUTHN_LEVEL_CALL, /* DWORD dwAuthnLevel */
        RPC_C_IMP_LEVEL_IMPERSONATE, /* DWORD dwImpLevel */
        NULL, /* RPC_AUTH_IDENTITY_HANDLE pAuthInfo */
        EOAC_NONE); /* DWORD dwCapabilities */
    if (FAILED(hRes)) {
        _ftprintf(stderr, _T("Error: CoSetProxyBlanket returned %#lx\n"), hRes);
        goto cleanup;
    }

    /* Now, do some stuff with the WMI connection */
    _tprintf(_T("Connection to WMI through ROOT\\CIMV2 was successful.\n"));

    if (!dump_running_processes(pSvc)) {
        bRes = FALSE;
    }
    if (!dump_disk_drives(pSvc)) {
        bRes = FALSE;
    }
    if (!dump_logical_disks(pSvc)) {
        bRes = FALSE;
    }

cleanup:
    if (pSvc) {
        IWbemServices_Release(pSvc);
    }
    if (pLoc) {
        IWbemLocator_Release(pLoc);
    }
    CoUninitialize();
    return (SUCCEEDED(hRes) && bRes) ? EXIT_SUCCESS : EXIT_FAILURE;
}
