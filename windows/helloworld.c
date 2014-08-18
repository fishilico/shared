/**
 * Display "Hello, world!" in a message box
 */
#include <windows.h>
#include <tchar.h>

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
    MessageBox(NULL, _T("Hello, world!"), _T("Hello world box"), MB_ICONINFORMATION | MB_OK);
    return 0;
}
