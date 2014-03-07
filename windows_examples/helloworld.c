/**
 * Display "Hello, world!" in a message box
 */
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    MessageBox(NULL, TEXT("Hello, world!"), TEXT("Hello world box"), MB_ICONINFORMATION | MB_OK);
    return 0;
}
