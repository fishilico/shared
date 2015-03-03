/**
 * Display "Hello, world!" in a message box
 */
#include <tchar.h>
#include <windows.h>

/* Avoid -Wunused-parameter but keep the code mostly clean */
#define _u __attribute__ ((unused))

int WINAPI _tWinMain(HINSTANCE hInstance _u, HINSTANCE hPrevInstance _u, LPTSTR lpCmdLine _u, int nCmdShow _u)
{
    MessageBox(NULL, _T("Hello, world!"), _T("Hello world box"), MB_ICONINFORMATION | MB_OK);
    return 0;
}
