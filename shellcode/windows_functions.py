#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# Copyright (c) 2019 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
List of usual modules and functions used by Windows programs

This helps to get which function is used by some shellcodes that resolve their
imported functions using hashes.

On a Linux system, information about available Windows libraries and functions
can be found in /usr/lib/wine/fakedlls/*.dll and /usr/lib/wine/lib*.def.

@author: Nicolas Iooss
@license: MIT
"""
MODULE_NAMES = (
    'gdi32.dll',
    'imm32.dll',
    'KERNEL32.dll',
    'kernelbase.dll',
    'msvcrt.dll',
    'ntdll.dll',
    'user32.dll',
    'version.dll',
    'winsock.dll',
    'ws2_32.dll',
)
FUNCTION_NAMES = (
    'accept',
    'accept4',
    'AcceptEx',
    'bind',
    'close',
    'CloseHandle',
    'closesocket',
    'connect',
    'CreateFileA',
    'CreateFileExA',
    'CreateFileExW',
    'CreateFileW',
    'CreateProcessA',
    'CreateProcessAsUserA',
    'CreateProcessAsUserW',
    'CreateProcessW',
    'CreateRemoteThread',
    'CreateRemoteThreadEx',
    'CreateThread',
    'DeviceIoControl',
    'ExitProcess',
    'ExitThread',
    'GetAcceptExSockaddrs',
    'GetCurrentProcess',
    'gethostbyaddr',
    'gethostbyname',
    'GetHostNameW',
    'getpeername',
    'GetProcAddress',
    'GetProcessHeap',
    'getsockname',
    'getsockopt',
    'GetStdHandle',
    'HeapAlloc',
    'HeapFree',
    'htonl',
    'htons',
    'inet_addr',
    'inet_aton',
    'inet_ntoa',
    'inet_ntop',
    'inet_pton',
    'ioctl',
    'ioctlsocket',
    'IsDebuggerPresent',
    'listen',
    'LoadLibraryA',
    'LoadLibraryW',
    'ntohl',
    'ntohs',
    'NtQueryInformationProcess',
    'open',
    'OpenProcess',
    'OpenThread',
    'ReadFile',
    'ReadProcessMemory',
    'recv',
    'recvfrom',
    'send',
    'sendto',
    'setsockopt',
    'shutdown',
    'socket',
    'TransmitFile',
    'VirtualAlloc',
    'VirtualAllocEx',
    'VirtualProtect',
    'VirtualProtectEx',
    'WaitForSingleObject',
    'WriteFile',
    'WriteProcessMemory',
    'WSAAccept',
    'WSAAddressToStringA',
    'WSAAddressToStringW',
    'WSAAsyncGetHostByAddr',
    'WSAAsyncGetHostByName',
    'WSAAsyncGetProtoByName',
    'WSAAsyncGetProtoByNumber',
    'WSAAsyncGetServByName',
    'WSAAsyncGetServByPort',
    'WSAAsyncSelect',
    'WSACancelAsyncRequest',
    'WSACancelBlockingCall',
    'WSACleanup',
    'WSACloseEvent',
    'WSAConnect',
    'WSAConnectByList',
    'WSAConnectByNameA',
    'WSAConnectByNameW',
    'WSACreateEvent',
    'WSADuplicateSocketA',
    'WSADuplicateSocketW',
    'WSAEnumNameSpaceProvidersA',
    'WSAEnumNameSpaceProvidersExA',
    'WSAEnumNameSpaceProvidersExW',
    'WSAEnumNameSpaceProvidersW',
    'WSAEnumNetworkEvents',
    'WSAEnumProtocolsA',
    'WSAEnumProtocolsW',
    'WSAEventSelect',
    'WSAGetLastError',
    'WSAGetOverlappedResult',
    'WSAGetQOSByName',
    'WSAGetServiceClassInfoA',
    'WSAGetServiceClassInfoW',
    'WSAGetServiceClassNameByClassIdA',
    'WSAGetServiceClassNameByClassIdW',
    'WSAHtonl',
    'WSAHtons',
    'WSAInstallServiceClassA',
    'WSAInstallServiceClassW',
    'WSAIoctl',
    'WSAIsBlocking',
    'WSAJoinLeaf',
    'WSALookupServiceBeginA',
    'WSALookupServiceBeginW',
    'WSALookupServiceEnd',
    'WSALookupServiceNextA',
    'WSALookupServiceNextW',
    'WSANSPIoctl',
    'WSANtohl',
    'WSANtohs',
    'WSAPoll',
    'WSAProviderConfigChange',
    'WSARecv',
    'WSARecvDisconnect',
    'WSARecvEx',
    'WSARecvFrom',
    'WSARemoveServiceClass',
    'WSAResetEvent',
    'WSASend',
    'WSASendDisconnect',
    'WSASendMsg',
    'WSASendTo',
    'WSASetBlockingHook',
    'WSASetEvent',
    'WSASetLastError',
    'WSASetServiceA',
    'WSASetServiceW',
    'WSASocketA',
    'WSASocketW',
    'WSAStartup',
    'WSAStringToAddressA',
    'WSAStringToAddressW',
    'WSAUnhookBlockingHook',
    'WSAWaitForMultipleEvents',
)


def reverse32_bits(num):
    """Reverse the bits of a 32-bit number"""
    num = ((num & 0x55555555) << 1) | ((num & 0xaaaaaaaa) >> 1)
    num = ((num & 0x33333333) << 2) | ((num & 0xcccccccc) >> 2)
    num = ((num & 0x0f0f0f0f) << 4) | ((num & 0xf0f0f0f0) >> 4)
    num = ((num & 0x00ff00ff) << 8) | ((num & 0xff00ff00) >> 8)
    num = ((num & 0x0000ffff) << 16) | ((num & 0xffff0000) >> 16)
    assert (num & ~0xffffffff) == 0
    return num


CRC32_REV_POLYNOM = reverse32_bits(0x1edc6f41)


def crc32c_rev(name):
    """Compute the reversed CRC32C of the given function name"""
    value = 0
    for char in name:
        value ^= ord(char)
        for _ in range(8):
            carry = value & 1
            value = value >> 1
            if carry:
                value ^= CRC32_REV_POLYNOM
    return value

# Hash values used in shellcodes
assert crc32c_rev('CreateProcessA') == 0x7a1a0524
assert crc32c_rev('WaitForSingleObject') == 0xd8945176
