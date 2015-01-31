/**
 * _start implementation for a "bare" Windows executable which does not use
 * the standard runtime environment.
 */
#ifndef NOIMPORT_START_H
#define NOIMPORT_START_H

/**
 * Depending on the chosen subsystem at link-time, the entry point has different names
 *
 * More information on how binutils' ld find the entry point can be got by
 * reading the code of the set_entry_point() function in ld/emultempl/pe.em:
 * https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=ld/emultempl/pe.em
 */
void __cdecl WinMainCRTStartup(void) __attribute__ ((alias("_start")));
void __cdecl mainCRTStartup(void) __attribute__ ((alias("_start")));
void __cdecl _start(void) __attribute__((noreturn));
static int _main(void);

/**
 * Call _main without any parameter and exit with its return value
 */
void __cdecl _start(void)
{
    int status = _main();
    while (TRUE) {
        _ExitProcess(status);
    }
}

#endif /* NOIMPORT_START_H */
