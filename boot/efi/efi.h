/**
 * Define API for EFI functions
 *
 * For more generic use case, see also: http://gnu-efi.sourceforge.net/
 */
#ifndef EFI_H
#define EFI_H

#include <stddef.h>
#include <stdint.h>

#define EFI_SUCCESS 0
#define EFIAPI
#define IN
#define OUT
#define OPTIONAL

#if defined(__x86_64__)
#   define EFIERR(a) (0x8000000000000000 | (a))
#elif defined(__i386__) || defined(__arm__)
#   define EFIERR(a) (0x80000000 | (a))
#else
#    error Unsupported architecture
#endif

#define EFI_ERROR(a) (((INTN) (a)) < 0)
#define EFI_SUCCESS             0
#define EFI_LOAD_ERROR              EFIERR(1)
#define EFI_INVALID_PARAMETER       EFIERR(2)
#define EFI_UNSUPPORTED             EFIERR(3)
#define EFI_BAD_BUFFER_SIZE         EFIERR(4)
#define EFI_BUFFER_TOO_SMALL        EFIERR(5)
#define EFI_NOT_READY               EFIERR(6)
#define EFI_DEVICE_ERROR            EFIERR(7)
#define EFI_WRITE_PROTECTED         EFIERR(8)
#define EFI_OUT_OF_RESOURCES        EFIERR(9)
#define EFI_VOLUME_CORRUPTED        EFIERR(10)
#define EFI_VOLUME_FULL             EFIERR(11)
#define EFI_NO_MEDIA                EFIERR(12)
#define EFI_MEDIA_CHANGED           EFIERR(13)
#define EFI_NOT_FOUND               EFIERR(14)
#define EFI_ACCESS_DENIED           EFIERR(15)
#define EFI_NO_RESPONSE             EFIERR(16)
#define EFI_NO_MAPPING              EFIERR(17)
#define EFI_TIMEOUT                 EFIERR(18)
#define EFI_NOT_STARTED             EFIERR(19)
#define EFI_ALREADY_STARTED         EFIERR(20)
#define EFI_ABORTED                 EFIERR(21)
#define EFI_ICMP_ERROR              EFIERR(22)
#define EFI_TFTP_ERROR              EFIERR(23)
#define EFI_PROTOCOL_ERROR          EFIERR(24)
#define EFI_INCOMPATIBLE_VERSION    EFIERR(25)
#define EFI_SECURITY_VIOLATION      EFIERR(26)
#define EFI_CRC_ERROR               EFIERR(27)
#define EFI_END_OF_MEDIA            EFIERR(28)
#define EFI_END_OF_FILE             EFIERR(31)
#define EFI_INVALID_LANGUAGE        EFIERR(32)
#define EFI_COMPROMISED_DATA        EFIERR(33)

typedef void VOID;
typedef long INTN;
typedef unsigned long UINTN;
typedef int8_t INT8;
typedef int16_t INT16;
typedef int32_t INT32;
typedef int64_t INT64;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef UINT8 BOOLEAN;
typedef UINT8 CHAR8;
typedef UINT16 CHAR16;

#ifndef CONST
#    define CONST const
#endif
#ifndef TRUE
#    define TRUE ((BOOLEAN)1)
#    define FALSE ((BOOLEAN)0)
#endif
#ifndef NULL
#    define NULL ((VOID *)0)
#endif

typedef VOID *EFI_EVENT;
typedef VOID *EFI_HANDLE;
typedef UINTN EFI_STATUS;
typedef UINTN EFI_TPL;
typedef UINT64 EFI_PHYSICAL_ADDRESS;
typedef UINT64 EFI_VIRTUAL_ADDRESS;

typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8 Data4[8];
} EFI_GUID;

typedef struct {
    UINT16 Year;
    UINT8 Month;
    UINT8 Day;
    UINT8 Hour;
    UINT8 Minute;
    UINT8 Second;
    UINT8 Pad1;
    UINT32 Nanosecond;
    INT16 TimeZone;
    UINT8 Daylight;
    UINT8 Pad2;
} EFI_TIME;

typedef struct _EFI_TABLE_HEARDER {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

/* SIMPLE_INPUT_INTERFACE definitions */

struct _SIMPLE_INPUT_INTERFACE;

typedef struct {
    UINT16 ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

typedef struct _SIMPLE_INPUT_INTERFACE {
    EFI_STATUS (EFIAPI *Reset) (IN struct _SIMPLE_INPUT_INTERFACE *This, IN BOOLEAN ExtendedVerification);
    EFI_STATUS (EFIAPI *ReadKeyStroke) (IN struct _SIMPLE_INPUT_INTERFACE *This, OUT EFI_INPUT_KEY *Key);
    EFI_EVENT WaitForKey;
} SIMPLE_INPUT_INTERFACE;

/* SIMPLE_TEXT_OUTPUT_INTERFACE definitions */

struct _SIMPLE_TEXT_OUTPUT_INTERFACE;

typedef struct {
    INT32 MaxMode;
    INT32 Mode;
    INT32 Attribute;
    INT32 CursorColumn;
    INT32 CursorRow;
    BOOLEAN CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef struct _SIMPLE_TEXT_OUTPUT_INTERFACE {
    EFI_STATUS (EFIAPI *Reset) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN BOOLEAN ExtendedVerification);

    EFI_STATUS (EFIAPI *OutputString) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN const CHAR16 *String);
    EFI_STATUS (EFIAPI *TestString) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN const CHAR16 *String);

    EFI_STATUS (EFIAPI *QueryMode) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN UINTN ModeNumber,
                                    OUT UINTN *Columns, OUT UINTN *Rows);
    EFI_STATUS (EFIAPI *SetMode) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN UINTN ModeNumber);
    EFI_STATUS (EFIAPI *SetAttribute) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN UINTN Attribute);

    EFI_STATUS (EFIAPI *ClearScreen) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This);
    EFI_STATUS (EFIAPI *SetCursorPosition) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN UINTN Column,
                                            IN UINTN Row);
    EFI_STATUS (EFIAPI *EnableCursor) (IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This, IN BOOLEAN Enable);

    SIMPLE_TEXT_OUTPUT_MODE *Mode;
} SIMPLE_TEXT_OUTPUT_INTERFACE;

/* EFI_RUNTIME_SERVICES definitions */

typedef struct {
    UINT32 Resolution;
    UINT32 Accuracy;
    BOOLEAN SetsToZero;
} EFI_TIME_CAPABILITIES;

typedef struct {
    UINT32 Type;
    UINT32 Pad;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    EFI_VIRTUAL_ADDRESS VirtualStart;
    UINT64 NumberOfPages;
    UINT64 Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef enum {
    EfiResetCold,
    EfiResetWarm,
    EfiResetShutdown
} EFI_RESET_TYPE;

typedef struct _EFI_RUNTIME_SERVICES {
    EFI_TABLE_HEADER Hdr;

     EFI_STATUS (EFIAPI *GetTime) (OUT EFI_TIME *Time, OUT EFI_TIME_CAPABILITIES *Capabilities OPTIONAL);
     EFI_STATUS (EFIAPI *SetTime) (IN const EFI_TIME *Time);
     EFI_STATUS (EFIAPI *GetWakeupTime) (OUT BOOLEAN *Enabled, OUT BOOLEAN *Pending, OUT EFI_TIME *Time);
     EFI_STATUS (EFIAPI *SetWakeupTime) (IN BOOLEAN Enable, IN const EFI_TIME *Time OPTIONAL);

     EFI_STATUS (EFIAPI *SetVirtualAddressMap) (IN UINTN MemoryMapSize, IN UINTN DescriptorSize,
                                                IN UINT32 DescriptorVersion, IN EFI_MEMORY_DESCRIPTOR *VirtualMap);
     EFI_STATUS (EFIAPI *ConvertPointer) (IN UINTN DebugDisposition, IN OUT VOID **Address);

     EFI_STATUS (EFIAPI *GetVariable) (IN const CHAR16 *VariableName, IN const EFI_GUID *VendorGuid,
                                       OUT UINT32 *Attributes OPTIONAL, IN OUT UINTN *DataSize, OUT VOID *Data);
     EFI_STATUS (EFIAPI *GetNextVariableName) (IN OUT UINTN *VariableNameSize, IN OUT CHAR16 *VariableName,
                                               IN OUT EFI_GUID *VendorGuid);
     EFI_STATUS (EFIAPI *SetVariable) (IN const CHAR16 *VariableName, IN const EFI_GUID *VendorGuid, IN UINT32 Attributes,
                                       IN UINTN DataSize, IN VOID *Data);

     EFI_STATUS (EFIAPI *GetNextHighMonotonicCount) (OUT UINT32 *HighCount);
     EFI_STATUS (EFIAPI *ResetSystem) (IN EFI_RESET_TYPE ResetType, IN EFI_STATUS ResetStatus, IN UINTN DataSize,
                                       IN const CHAR16 *ResetData OPTIONAL);
} EFI_RUNTIME_SERVICES;

/* EFI_BOOT_SERVICES definitions */

typedef enum {
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
    MaxAllocateType
} EFI_ALLOCATE_TYPE;

typedef enum {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef VOID (EFIAPI *EFI_EVENT_NOTIFY) (IN EFI_EVENT Event, IN VOID *Context);

typedef enum {
    TimerCancel,
    TimerPeriodic,
    TimerRelative,
    TimerTypeMax
} EFI_TIMER_DELAY;

typedef enum {
    EFI_NATIVE_INTERFACE,
    EFI_PCODE_INTERFACE
} EFI_INTERFACE_TYPE;

typedef enum {
    AllHandles,
    ByRegisterNotify,
    ByProtocol
} EFI_LOCATE_SEARCH_TYPE;

typedef struct _EFI_DEVICE_PATH {
    UINT8 Type;
    UINT8 SubType;
    UINT8 Length[2];
} EFI_DEVICE_PATH;

typedef struct _EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;

    EFI_TPL (EFIAPI *RaiseTPL) (IN EFI_TPL NewTpl);
    VOID (EFIAPI *RestoreTPL) (IN EFI_TPL OldTpl);

    EFI_STATUS (EFIAPI *AllocatePages) (IN EFI_ALLOCATE_TYPE Type, IN EFI_MEMORY_TYPE MemoryType, IN UINTN NoPages,
                                        OUT EFI_PHYSICAL_ADDRESS *Memory);
    EFI_STATUS (EFIAPI *FreePages) (IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN NoPages);
    EFI_STATUS (EFIAPI *GetMemoryMap) (IN OUT UINTN *MemoryMapSize, IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap,
                                       OUT UINTN *MapKey, OUT UINTN *DescriptorSize, OUT UINT32 *DescriptorVersion);
    EFI_STATUS (EFIAPI *AllocatePool) (IN EFI_MEMORY_TYPE PoolType, IN UINTN Size, OUT VOID **Buffer);
    EFI_STATUS (EFIAPI *FreePool) (IN VOID *Buffer);

    EFI_STATUS (EFIAPI *CreateEvent) (IN UINT32 Type, IN EFI_TPL NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction,
                                      IN VOID *NotifyContext, OUT EFI_EVENT *Event);
    EFI_STATUS (EFIAPI *SetTimer) (IN EFI_EVENT Event, IN EFI_TIMER_DELAY Type, IN UINT64 TriggerTime);

    EFI_STATUS (EFIAPI *WaitForEvent) (IN UINTN NumberOfEvents, IN EFI_EVENT *Event, OUT UINTN *Index);
    EFI_STATUS (EFIAPI *SignalEvent) (IN EFI_EVENT Event);
    EFI_STATUS (EFIAPI *CloseEvent) (IN EFI_EVENT Event);
    EFI_STATUS (EFIAPI *CheckEvent) (IN EFI_EVENT Event);

    EFI_STATUS (EFIAPI *InstallProtocolInterface) (IN OUT EFI_HANDLE *Handle, IN EFI_GUID *Protocol,
                                                   IN EFI_INTERFACE_TYPE InterfaceType, IN VOID *Interface);
    EFI_STATUS (EFIAPI *ReinstallProtocolInterface) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol,
                                                     IN VOID *OldInterface, IN VOID *NewInterface);
    EFI_STATUS (EFIAPI *UninstallProtocolInterface) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol,
                                                     IN VOID *Interface);
    EFI_STATUS (EFIAPI *HandleProtocol) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);
    EFI_STATUS (EFIAPI *PCHandleProtocol) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);
    EFI_STATUS (EFIAPI *RegisterProtocolNotify) (IN EFI_GUID *Protocol, IN EFI_EVENT Event, OUT VOID **Registration);
    EFI_STATUS (EFIAPI *LocateHandle) (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol OPTIONAL,
                                       IN VOID *SearchKey OPTIONAL, IN OUT UINTN *BufferSize,
                                       OUT EFI_HANDLE *Buffer);
    EFI_STATUS (EFIAPI *LocateDevicePath) (IN EFI_GUID *Protocol, IN OUT EFI_DEVICE_PATH **DevicePath,
                                           OUT EFI_HANDLE *Device);
    EFI_STATUS (EFIAPI *InstallConfigurationTable) (IN EFI_GUID *Guid, IN VOID *Table);

    EFI_STATUS (EFIAPI *LoadImage) (IN BOOLEAN BootPolicy, IN EFI_HANDLE ParentImageHandle,
                                    IN EFI_DEVICE_PATH *FilePath, IN VOID *SourceBuffer OPTIONAL,
                                    IN UINTN SourceSize, OUT EFI_HANDLE *ImageHandle);
    EFI_STATUS (EFIAPI *StartImage) (IN EFI_HANDLE ImageHandle, OUT UINTN *ExitDataSize,
                                     OUT CHAR16 **ExitData OPTIONAL);
    EFI_STATUS (EFIAPI *Exit) (IN EFI_HANDLE ImageHandle, IN EFI_STATUS ExitStatus, IN UINTN ExitDataSize,
                               IN CHAR16 *ExitData OPTIONAL);
    EFI_STATUS (EFIAPI *UnloadImage) (IN EFI_HANDLE ImageHandle);
    EFI_STATUS (EFIAPI *ExitBootServices) (IN EFI_HANDLE ImageHandle, IN UINTN MapKey);

    VOID *GetNextMonotonicCount;
    VOID *Stall;
    VOID *SetWatchdogTimer;

    VOID *ConnectController;
    VOID *DisconnectController;

    VOID *OpenProtocol;
    VOID *CloseProtocol;
    VOID *OpenProtocolInformation;

    VOID *ProtocolsPerHandle;
    VOID *LocateHandleBuffer;
    VOID *LocateProtocol;
    VOID *InstallMultipleProtocolInterfaces;
    VOID *UninstallMultipleProtocolInterfaces;

    VOID *CalculateCrc32;

    VOID *CopyMem;
    VOID *SetMem;
    VOID *CreateEventEx;
} EFI_BOOT_SERVICES;

/* EFI_SYSTEM_TABLE definition */

typedef struct _EFI_CONFIGURATION_TABLE {
    EFI_GUID VendorGuid;
    VOID *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct _EFI_SYSTEM_TABLE {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    SIMPLE_INPUT_INTERFACE *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    SIMPLE_TEXT_OUTPUT_INTERFACE *ConOut;
    EFI_HANDLE StandardErrorHandle;
    SIMPLE_TEXT_OUTPUT_INTERFACE *StdErr;
    EFI_RUNTIME_SERVICES *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;

#define EFI_IMAGE_INFORMATION_REVISION 0x1000
typedef struct {
    UINT32 Revision;
    EFI_HANDLE ParentHandle;
    struct _EFI_SYSTEM_TABLE *SystemTable;

    EFI_HANDLE DeviceHandle;
    EFI_DEVICE_PATH *FilePath;
    VOID *Reserved;

    UINT32 LoadOptionsSize;
    VOID *LoadOptions;

    VOID *ImageBase;
    UINT64 ImageSize;
    EFI_MEMORY_TYPE ImageCodeType;
    EFI_MEMORY_TYPE ImageDataType;

    EFI_STATUS (EFIAPI *Unload) (IN EFI_HANDLE ImageHandle);
} EFI_LOADED_IMAGE;


/* efi_call */
#if defined __x86_64__
/* Put the arguments of the EFI call in the following places:
 * * arg1 in rcx
 * * arg2 in rdx
 * * arg3 in r8 = arg3
 * * arg4 in r9 = arg4
 * * arg5 in 32(%rsp)
 * * arg6 in 40(%rsp)
 * allocate on stack enough space for these arguments, so that 8(%rsp) is
 * aligned to 16 (ELF convention) => 40 bytes (0x28)
 *
 * The following registers are volatile and must be considered destroyed on function calls:
 *      rax, rcx, rdx, r8, r9, r10, r11
 * The following registers are nonvolatile and must be saved and restored by a function that uses them:
 *      rbx, rbp, rdi, rsi, rsp, r12, r13, r14, r15
 */
static inline UINT64 _efi_call4(VOID *func, UINT64 arg1, UINT64 arg2, UINT64 arg3, UINT64 arg4)
{
    UINT64 result;
    register long r9 __asm__("r9") = arg4;
    register long r8 __asm__("r8") = arg3;
    __asm__ volatile ("subq $0x28, %%rsp ; call *%1 ; addq $0x28, %%rsp"
        : "=a" (result)
        : "r" (func), "c" (arg1), "d" (arg2), "r" (r8), "r" (r9)
#if defined(__GNUC__) && !defined(__clang__)
        /* GCC doesn't like clobbering the parameter registers */
        : "cc", "memory", "%r10", "%r11");
#else
        : "cc", "memory", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11");
#endif
    return result;
}
static inline UINT64 _efi_call5(VOID *func, UINT64 arg1, UINT64 arg2, UINT64 arg3, UINT64 arg4, UINT64 arg5)
{
    UINT64 result;
    register long r9 __asm__("r9") = arg4;
    register long r8 __asm__("r8") = arg3;
    /* Note: don't use "g" for arg5 as some compilers might want to use %rsp-relative pointer */
    __asm__ volatile ("subq $0x28, %%rsp ; movq %6, 0x20(%%rsp) ; call *%1 ; addq $0x28, %%rsp"
        : "=a" (result)
        : "r" (func), "c" (arg1), "d" (arg2), "r" (r8), "r" (r9), "r" (arg5)
#if defined(__GNUC__) && !defined(__clang__)
        : "cc", "memory", "%r10", "%r11");
#else
        : "cc", "memory", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11");
#endif
    return result;
}
#define efi_call5(func, arg1, arg2, arg3, arg4, arg5) _efi_call5((func), \
    (UINT64)(arg1), (UINT64)(arg2), (UINT64)(arg3), (UINT64)(arg4), (UINT64)(arg5))
#define efi_call4(func, arg1, arg2, arg3, arg4) _efi_call4((func), \
    (UINT64)(arg1), (UINT64)(arg2), (UINT64)(arg3), (UINT64)(arg4))
#define efi_call3(func, arg1, arg2, arg3) efi_call4((func), (arg1), (arg2), (arg3), 0)
#define efi_call2(func, arg1, arg2) efi_call3((func), (arg1), (arg2), 0)
#define efi_call1(func, arg1) efi_call2((func), (arg1), 0)
#define efi_call0(func) efi_call1((func), 0)

#elif defined(__i386__) || defined(__arm__)
/* No wrapper, use the stack (x86) or registers (arm) to pass parameters */
#define efi_call5(func, arg1, arg2, arg3, arg4, arg5) ((func)((arg1), (arg2), (arg3), (arg4), (arg5)))
#define efi_call4(func, arg1, arg2, arg3, arg4) ((func)((arg1), (arg2), (arg3), (arg4)))
#define efi_call3(func, arg1, arg2, arg3) ((func)((arg1), (arg2), (arg3)))
#define efi_call2(func, arg1, arg2) ((func)((arg1), (arg2)))
#define efi_call1(func, arg1)((func)((arg1)))
#define efi_call0(func) ((func)())

#else
#    error Unsupported architecture
#endif

/* CRT and lib */
extern EFI_SYSTEM_TABLE *ST;
extern EFI_BOOT_SERVICES *BS;
extern EFI_RUNTIME_SERVICES *RT;
extern EFI_MEMORY_TYPE PoolAllocationType;

extern EFI_GUID LoadedImageProtocol;

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab);

void *memset(void *s, int c, UINTN n);
void print(const CHAR16 *text);
void waitkey(BOOLEAN message);
void * pool_alloc(UINTN size);
void pool_free(void *buffer);

#endif /* EFI_H */
