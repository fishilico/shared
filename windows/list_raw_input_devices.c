/**
 * List the raw input devices that have been set up.
 *
 * Documentation:
 * * https://docs.microsoft.com/en-gb/windows/win32/api/winuser/nf-winuser-getrawinputdevicelist
 * * https://docs.microsoft.com/en-gb/windows/win32/api/winuser/nf-winuser-getrawinputdeviceinfoa
 */
#include "common.h"

/**
 * Wrap GetRawInputDeviceList to allocate memory
 */
static BOOL GetRawInputDeviceListWithAlloc(PRAWINPUTDEVICELIST *ppRawInputDeviceList, UINT *puiNumDevices)
{
    UINT uiNumDevices = 0, numStored;
    PRAWINPUTDEVICELIST pBuffer = NULL;

    if (GetRawInputDeviceList(NULL, &uiNumDevices, sizeof(RAWINPUTDEVICELIST)) != 0) {
        print_winerr(_T("GetRawInputDeviceList"));
        return FALSE;
    }
    if (!uiNumDevices) {
        _ftprintf(stderr, _T("Error: GetRawInputDeviceList returned an empty list\n"));
        return FALSE;
    }

    pBuffer = HeapAlloc(GetProcessHeap(), 0, uiNumDevices * sizeof(TCHAR));
    if (!pBuffer) {
        print_winerr(_T("HeapAlloc"));
        return FALSE;
    }

    numStored = GetRawInputDeviceList(pBuffer, &uiNumDevices, sizeof(RAWINPUTDEVICELIST));
    if (numStored == -1U) {
        print_winerr(_T("GetRawInputDeviceList"));
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return FALSE;
    }
    if (numStored != uiNumDevices) {
        _ftprintf(stderr, _T("Error: GetRawInputDeviceList returned an unexpected number of items: %u != %u\n"),
                  numStored, uiNumDevices);
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return FALSE;
    }

    *ppRawInputDeviceList = pBuffer;
    *puiNumDevices = uiNumDevices;
    return TRUE;
}

/**
 * Wrap GetRawInputDeviceInfo to allocate memory for RIDI_DEVICENAME (as string)
 * and for other commands (as bytes)
 */
static PVOID GetRawInputDeviceInfoWithAlloc(HANDLE hDevice, UINT uiCommand, UINT *pSize)
{
    UINT uRetval;
    LPTSTR pBuffer;
    UINT uiSize = 0, uiSize2 = 0;

    if (GetRawInputDeviceInfo(hDevice, uiCommand, NULL, &uiSize) != 0) {
        print_winerr(_T("GetRawInputDeviceList"));
        return FALSE;
    }

    if (uiCommand == RIDI_DEVICENAME) {
        pBuffer = HeapAlloc(GetProcessHeap(), 0, (uiSize + 1) * sizeof(TCHAR));
    } else {
        pBuffer = HeapAlloc(GetProcessHeap(), 0, uiSize);
    }
    if (!pBuffer) {
        print_winerr(_T("HeapAlloc"));
        return NULL;
    }
    uiSize2 = uiSize;
    uRetval = GetRawInputDeviceInfo(hDevice, uiCommand, pBuffer, &uiSize2);
    if (uRetval == -1U) {
        print_winerr(_T("GetRawInputDeviceInfo"));
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return NULL;
    }
    assert(uiSize == uiSize2);
    if (uiCommand == RIDI_DEVICENAME) {
        ((LPTSTR)pBuffer)[uiSize] = 0;
    }

    if (pSize)
        *pSize = uiSize;
    return pBuffer;
}


int _tmain(void)
{
    PRAWINPUTDEVICELIST pRawInputDeviceList = NULL;
    UINT uiNumDevices = 0, i;
    LPTSTR szDeviceName;
    RID_DEVICE_INFO *pDeviceInfo;
    UINT uiDevInfoSize;

    if (!GetRawInputDeviceListWithAlloc(&pRawInputDeviceList, &uiNumDevices)) {
        return 1;
    }
    _tprintf(_T("Found %u raw input devices\n"), uiNumDevices);
    for (i = 0; i < uiNumDevices; i++) {
        szDeviceName = GetRawInputDeviceInfoWithAlloc(pRawInputDeviceList[i].hDevice, RIDI_DEVICENAME, NULL);
        uiDevInfoSize = 0;
        pDeviceInfo = GetRawInputDeviceInfoWithAlloc(pRawInputDeviceList[i].hDevice, RIDI_DEVICEINFO, &uiDevInfoSize);

        if (!pDeviceInfo) {
            _tprintf(_T("[%2d] %s: no device information\n"), i, szDeviceName);
        } else {
            assert(pDeviceInfo->cbSize == (DWORD)uiDevInfoSize);
            assert(pDeviceInfo->dwType == pRawInputDeviceList[i].dwType);
            switch (pDeviceInfo->dwType) {
                case RIM_TYPEMOUSE: /* 0 */
                    _tprintf(_T("[%2d] Mouse: %s\n"), i, szDeviceName);
                    _tprintf(_T("  * ID: %#lx\n"), pDeviceInfo->mouse.dwId);
                    _tprintf(_T("  * Number of buttons: %lu\n"),
                             pDeviceInfo->mouse.dwNumberOfButtons);
                    _tprintf(_T("  * Sample rate (data points per second): %lu\n"),
                             pDeviceInfo->mouse.dwSampleRate);
                    /* Old Mingw-gcc did not know about fHasHorizontalWheel
                    _tprintf(_T("  * Has horizontal wheel: %#s\n"),
                             pDeviceInfo->mouse.fHasHorizontalWheel ? _T("yes") : _T("no"));
                    */
                    break;
                case RIM_TYPEKEYBOARD: /* 1 */
                    _tprintf(_T("[%2d] Keyboard: %s\n"), i, szDeviceName);
                    _tprintf(_T("  * Type: %#lx\n"), pDeviceInfo->keyboard.dwType);
                    _tprintf(_T("  * Subtype: %#lx\n"), pDeviceInfo->keyboard.dwSubType);
                    _tprintf(_T("  * Scan code mode: %#lx\n"), pDeviceInfo->keyboard.dwKeyboardMode);
                    _tprintf(_T("  * Number of function keys: %lu\n"), pDeviceInfo->keyboard.dwNumberOfFunctionKeys);
                    _tprintf(_T("  * Number of indicators: %lu\n"), pDeviceInfo->keyboard.dwNumberOfIndicators);
                    _tprintf(_T("  * Number of keys total: %lu\n"), pDeviceInfo->keyboard.dwNumberOfKeysTotal);
                    break;
                case RIM_TYPEHID: /* 2 */
                    _tprintf(_T("[%2d] HID device: %s\n"), i, szDeviceName);
                    _tprintf(_T("  * Vendor ID: %#lx\n"), pDeviceInfo->hid.dwVendorId);
                    _tprintf(_T("  * Product ID: %#lx\n"), pDeviceInfo->hid.dwProductId);
                    _tprintf(_T("  * Version number: %#lx\n"), pDeviceInfo->hid.dwVersionNumber);
                    _tprintf(_T("  * Usage page: %#x\n"), pDeviceInfo->hid.usUsagePage);
                    _tprintf(_T("  * Usage: %#x\n"), pDeviceInfo->hid.usUsage);
                    break;
                default:
                    _tprintf(_T("[%2d] Unknown device type %lu: %s\n"), i, pDeviceInfo->dwType, szDeviceName);
            }
            HeapFree(GetProcessHeap(), 0, pDeviceInfo);
        }
        HeapFree(GetProcessHeap(), 0, szDeviceName);
    }
    HeapFree(GetProcessHeap(), 0, pRawInputDeviceList);
    return 0;
}
