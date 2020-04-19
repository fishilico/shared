#!/usr/bin/env python3
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
"""Decode BIOS measurements from TPM event log

Linux exposes this event log file in securityfs:
/sys/kernel/security/tpm0/binary_bios_measurements.
The Linux kernel module that exposes it has its source code on
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/char/tpm/eventlog/tpm2.c?h=v5.1

Windows records the TPM event log in C:\Windows\Logs\MeasuredBoot in files named
for example ``0000000042-0000000002.log`` for the 42th boot, 3rd wake-up after
sleep (probably).

The events are specified in https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/
"""
import argparse
import binascii
import collections
import hashlib
import platform
import struct
import sys
import uuid


try:
    import enum
    from pathlib import Path
except ImportError:
    # Modules enum and pathlib were introduced in Python 3.4
    assert sys.version_info < (3, 4)
    sys.stderr.write("This program cannot be run in Python<3.4 mode.\n")
    sys.exit(0)


# Descriptions for each Platform Configuration Register of a TPM
PCR_DESCRIPTIONS = {
    0: "CRTM (Core Root of Trust of Measurement), BIOS and Host Platform Extensions",
    1: "Host Platform Configuration (including BIOS configuration)",
    2: "Option ROM Code",
    3: "Option ROM Configuration and Data",
    4: "IPL (Initial Program Load) Code",
    5: "IPL (Initial Program Load) Data",
    6: "State Transition and Wake Events",
    7: "Host Platform Manufacturer Control",
    8: "Operating System [8]",
    9: "Operating System [9]",
    10: "Operating System [10]",
    11: "Operating System [11]",
    12: "Operating System [12]",
    13: "Operating System [13]",
    14: "Operating System [14]",
    15: "Operating System [15]",
    16: "Debug",
    17: "Localities, Trusted OS [17]",
    18: "Localities, Trusted OS [18]",
    19: "Localities, Trusted OS [19]",
    20: "Localities, Trusted OS [20]",
    21: "Localities, Trusted OS [21]",
    22: "Localities, Trusted OS [22]",
    23: "Applications specific",
}


@enum.unique
class TcgEventType(enum.IntEnum):
    """Type of an event in TCG event log"""
    EV_PREBOOT_CERT = 0x00000000
    EV_POST_CODE = 0x00000001
    EV_UNUSED = 0x00000002
    EV_NO_ACTION = 0x00000003
    EV_SEPARATOR = 0x00000004
    EV_ACTION = 0x00000005
    EV_EVENT_TAG = 0x00000006
    EV_S_CRTM_CONTENTS = 0x00000007
    EV_S_CRTM_VERSION = 0x00000008
    EV_CPU_MICROCODE = 0x00000009
    EV_PLATFORM_CONFIG_FLAGS = 0x0000000a
    EV_TABLE_OF_DEVICES = 0x0000000b
    EV_COMPACT_HASH = 0x0000000c
    EV_IPL = 0x0000000d
    EV_IPL_PARTITION_DATA = 0x0000000e
    EV_NONHOST_CODE = 0x0000000f
    EV_NONHOST_CONFIG = 0x00000010
    EV_NONHOST_INFO = 0x00000011
    EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012
    EV_EFI_EVENT_BASE = 0x80000000
    EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
    EV_EFI_VARIABLE_BOOT = 0x80000002
    EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
    EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
    EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
    EV_EFI_GPT_EVENT = 0x80000006
    EV_EFI_ACTION = 0x80000007
    EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008
    EV_EFI_HANDOFF_TABLES = 0x80000009
    EV_EFI_HCRTM_EVENT = 0x80000010
    EV_EFI_VARIABLE_AUTHORITY = 0x800000e0

    @classmethod
    def describe(cls, value):
        """Describe a TCG event by value"""
        try:
            return cls(value).name
        except ValueError:
            return "{}({:#x} = ?)".format(cls.__name__, value)


@enum.unique
class TpmAlgId(enum.IntEnum):
    """TPM_ALG_ID constants"""
    TPM_ALG_ERROR = 0x0000
    TPM_ALG_RSA = 0x0001
    TPM_ALG_SHA1 = 0x0004
    TPM_ALG_HMAC = 0x0005
    TPM_ALG_AES = 0x0006
    TPM_ALG_MGF1 = 0x0007
    TPM_ALG_KEYEDHASH = 0x0008
    TPM_ALG_XOR = 0x000a
    TPM_ALG_SHA256 = 0x000b
    TPM_ALG_SHA384 = 0x000c
    TPM_ALG_SHA512 = 0x000d
    TPM_ALG_NULL = 0x0010
    TPM_ALG_SM3_256 = 0x0012
    TPM_ALG_SM4 = 0x0013
    TPM_ALG_RSASSA = 0x0014
    TPM_ALG_RSAES = 0x0015
    TPM_ALG_RSAPSS = 0x0016
    TPM_ALG_OAEP = 0x0017
    TPM_ALG_ECDSA = 0x0018
    TPM_ALG_ECDH = 0x0019
    TPM_ALG_ECDAA = 0x001a
    TPM_ALG_SM2 = 0x001b
    TPM_ALG_ECSCHNORR = 0x001c
    TPM_ALG_ECMQV = 0x001d
    TPM_ALG_KDF1_SP800_56a = 0x0020
    TPM_ALG_KDF2 = 0x0021
    TPM_ALG_KDF1_SP800_108 = 0x0022
    TPM_ALG_ECC = 0x0023
    TPM_ALG_SYMCIPHER = 0x0025
    TPM_ALG_CTR = 0x0040
    TPM_ALG_OFB = 0x0041
    TPM_ALG_CBC = 0x0042
    TPM_ALG_CFB = 0x0043
    TPM_ALG_ECB = 0x0044

    @classmethod
    def get_name(cls, value):
        """Get the algorithm from the ID value"""
        try:
            name = cls(value).name
        except ValueError:
            return "{}({:#x} = ?)".format(cls.__name__, value)
        else:
            assert name.startswith('TPM_ALG_')
            return name[8:]

    def digest(self, data):
        """Compute the digest of the data"""
        if self == TpmAlgId.TPM_ALG_SHA1:
            return hashlib.sha1(data).digest()
        if self == TpmAlgId.TPM_ALG_SHA256:
            return hashlib.sha256(data).digest()
        raise NotImplementedError("Hash algorithm {} is not yet implemented".format(self))


def xx(data):
    """One-line hexadecimal representation of binary data"""
    return binascii.hexlify(data).decode('ascii')


class ComputedDigest:
    """Store a computed digest"""
    def __init__(self, alg_id, computed):
        self.alg_id = alg_id
        self.computed = computed

    def to_str(self, data_desc):
        """Generate a string with the description of the data"""
        return "{}({}) = {}".format(TpmAlgId.get_name(self.alg_id), data_desc, xx(self.computed))

    def matches(self, data, verbose=False):
        """Verify that the data matches with the digest"""
        data_digest = TpmAlgId(self.alg_id).digest(data)
        if data_digest == self.computed:
            return True
        if verbose:
            print("Warning: unexpected {} digest, computed {}".format(
                TpmAlgId.get_name(self.alg_id), xx(data_digest)))
        return False


class BinStream:
    """Binary stream of data, which is parsed"""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def is_end(self):
        """Is the end of stream reached?"""
        return self.pos >= len(self.data)

    def read_bytes(self, count):
        """Read a sequence of bytes from the input data"""
        assert count >= 0
        if self.pos + count > len(self.data):
            raise ValueError("Unable to read {} bytes ({}/{} remaining)".format(
                count, len(self.data) - self.pos, len(self.data)))
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def read_u8(self):
        """Read a 8-bit unsigned integer"""
        return self.read_bytes(1)[0]

    def read_u16(self):
        """Read a 16-bit unsigned integer"""
        return struct.unpack('<H', self.read_bytes(2))[0]

    def read_u32(self):
        """Read a 32-bit unsigned integer"""
        return struct.unpack('<I', self.read_bytes(4))[0]

    def read_u64(self):
        """Read a 64-bit unsigned integer"""
        return struct.unpack('<Q', self.read_bytes(8))[0]

    def read_uuid(self):
        """Read a 128-bit universally unique identifier"""
        return uuid.UUID(bytes_le=self.read_bytes(0x10))


def analyze_tpm_binary_bios_measurements(bin_path, fail_if_denied=True):
    """Analyze /sys/kernel/security/tpm0/binary_bios_measurements"""
    try:
        with bin_path.open('rb') as fbin:
            stream = BinStream(fbin.read())
    except PermissionError as exc:
        if fail_if_denied:
            print("Error: {}".format(exc))
            raise exc
        print("Non-fatal error: {}".format(exc))
        return

    pcr_states = collections.OrderedDict()

    is_first_event = True
    is_event03 = False  # Are the structures following tdTCG_PCR_EVENT2 format?
    spec_digest_sizes = {TpmAlgId.TPM_ALG_SHA1: 20}

    print("{}:".format(bin_path))
    while not stream.is_end():
        if is_first_event or not is_event03:
            # Read a tdTCG_PCR_EVENT structure
            pcr_index = stream.read_u32()
            event_type = stream.read_u32()
            sha1_digest = stream.read_bytes(20)  # SHA-1 digest
            digests = [ComputedDigest(TpmAlgId.TPM_ALG_SHA1, sha1_digest)]
            event_size = stream.read_u32()
            event_data = stream.read_bytes(event_size)
        else:
            # Read a tdTCG_PCR_EVENT2 structure
            pcr_index = stream.read_u32()
            event_type = stream.read_u32()
            # Read field "TPML_DIGEST_VALUES Digest"
            digest_count = stream.read_u32()
            digests = []
            for _ in range(digest_count):
                hash_alg = stream.read_u16()
                try:
                    hash_size = spec_digest_sizes[hash_alg]
                except KeyError:
                    raise ValueError("Unexpected hash algorithm {:#x} ({})".format(
                        hash_alg, TpmAlgId.get_name(hash_alg)))
                hash_digest = stream.read_bytes(hash_size)
                digests.append(ComputedDigest(hash_alg, hash_digest))
            event_size = stream.read_u32()
            event_data = stream.read_bytes(event_size)

        # Detect TCG_EfiSpecIdEventStruct
        if is_first_event and pcr_index == 0 and event_type == TcgEventType.EV_NO_ACTION:
            if sha1_digest == b'\0' * 20 and event_data.startswith(b'Spec ID Event03\0'):
                is_event03 = True
                data_stream = BinStream(event_data)
                spec_signature = data_stream.read_bytes(16)
                spec_platform_class = data_stream.read_u32()
                spec_version_minor = data_stream.read_u8()
                spec_version_major = data_stream.read_u8()
                spec_errata = data_stream.read_u8()
                spec_uintn_size = data_stream.read_u8()
                spec_num_algs = data_stream.read_u32()
                spec_digest_sizes = collections.OrderedDict()
                for _ in range(spec_num_algs):
                    hash_alg = data_stream.read_u16()
                    digest_size = data_stream.read_u16()
                    spec_digest_sizes[hash_alg] = digest_size
                    pcr_states[hash_alg] = []
                spec_vendor_info_size = data_stream.read_u8()
                spec_vendor_info = data_stream.read_bytes(spec_vendor_info_size)
                if not data_stream.is_end():
                    print("Warning: the spec has not been fully decoded ({}/{})".format(
                        data_stream.pos, len(data_stream.data)))

                print("[Header] {} class={:#x} version={}.{}.{}".format(
                    repr(spec_signature.decode().rstrip('\0')),
                    spec_platform_class,
                    spec_version_minor,
                    spec_version_major,
                    spec_errata))
                print("  * UINTN size: {}".format(spec_uintn_size))
                print("  * {} hash alorithms:".format(spec_num_algs))
                for hash_alg, digest_size in spec_digest_sizes.items():
                    print("    * {}: {} bytes".format(TpmAlgId.get_name(hash_alg), digest_size))
                if spec_vendor_info_size:
                    print("  * Vendor info: {}".format(repr(spec_vendor_info)))
                print("")

                is_first_event = False
                continue
        elif is_first_event:
            pcr_states[TpmAlgId.TPM_ALG_SHA1] = []

        is_first_event = False

        # Extend existing PCRs
        for computed_digest in digests:
            alg_id = computed_digest.alg_id
            alg_obj = TpmAlgId(alg_id)
            if len(pcr_states[alg_id]) <= pcr_index < 256:
                empty_digest = b'\0' * spec_digest_sizes[alg_id]
                pcr_states[alg_id] += [empty_digest] * (pcr_index + 1 - len(pcr_states[alg_id]))
            pcr_states[alg_id][pcr_index] = alg_obj.digest(
                pcr_states[alg_id][pcr_index] + computed_digest.computed)

        is_digest_of_data = all(computed_digest.matches(event_data) for computed_digest in digests)

        digest_desc = None
        data_desc = []

        # Handle EV_IPL from systemd, that only adds a single NUL byte instead of two
        # https://github.com/systemd/systemd/blob/v243/src/boot/efi/measure.c
        if is_digest_of_data:
            digest_desc = "event data"
        elif pcr_index == 8 and event_type == TcgEventType.EV_IPL:
            is_digest_of_data = all(computed_digest.matches(event_data + b'\0') for computed_digest in digests)
            if is_digest_of_data:
                digest_desc = "event data + '\\0'"

        if is_digest_of_data:
            if pcr_index == 0 and event_type == TcgEventType.EV_S_CRTM_VERSION:
                data_desc.append("(Version string of the CRTM)")

            elif event_type == TcgEventType.EV_EFI_VARIABLE_DRIVER_CONFIG:
                # EFI_VARIABLE_DATA structure => compute name for /sys/firmware/efi/efivars/
                if len(event_data) >= 0x20:
                    var_uuid = uuid.UUID(bytes_le=event_data[:0x10])
                    var_unicode_name_len, var_data_len = struct.unpack('<QQ', event_data[0x10:0x20])
                    var_name = event_data[0x20:0x20 + 2 * var_unicode_name_len].decode('utf-16le')
                    data_desc.append("* EFI Variable: {}-{}".format(var_name, var_uuid))
                    data_desc.append("* Data length: {} bytes".format(var_data_len))

        elif pcr_index == 0 and event_type == TcgEventType.EV_POST_CODE:
            # TCG_PCR_EVENT.digest = SHA-1 Hash of the POST CODE
            # TCG_PCR_EVENT.Event[1] = EFI_PLATFORM_FIRMWARE_BLOB structure (base + length)
            if event_data == b'ACPI DATA':
                digest_desc = "ACPI DATA"
            elif len(event_data) == 0x10:
                post_physaddr, post_length = struct.unpack('<QQ', event_data)
                digest_desc = "POST code"
                data_desc.append("* POST start: {:#x}".format(post_physaddr))
                data_desc.append("* POST length: {:#x} = {} kB".format(post_length, post_length / 1024.))
                data_desc.append("* (POST end: {:#x})".format(post_physaddr + post_length))

        elif pcr_index == 0 and event_type == TcgEventType.EV_S_CRTM_CONTENTS:
            # TCG_PCR_EVENT.digest = SHA-1 Hash of the CRTM content
            # TCG_PCR_EVENT.Event[1] = EFI_PLATFORM_FIRMWARE_BLOB structure (base + length)
            if len(event_data) == 0x10:
                crtm_physaddr, crtm_length = struct.unpack('<QQ', event_data)
                digest_desc = "CRTM Contents"
                data_desc.append("* CRTM start: {:#x}".format(crtm_physaddr))
                data_desc.append("* CRTM length: {:#x} = {} kB".format(crtm_length, crtm_length / 1024.))
                data_desc.append("* (CRTM end: {:#x})".format(crtm_physaddr + crtm_length))

        elif pcr_index == 5 and event_type == TcgEventType.EV_EFI_VARIABLE_BOOT:
            # EFI_VARIABLE_DATA structure => compute name for /sys/firmware/efi/efivars/
            if len(event_data) >= 0x20:
                digest_desc = "Boot variables"
                var_uuid = uuid.UUID(bytes_le=event_data[:0x10])
                var_unicode_name_len, var_data_len = struct.unpack('<QQ', event_data[0x10:0x20])
                var_name = event_data[0x20:0x20 + 2 * var_unicode_name_len].decode('utf-16le')
                data_desc.append("* EFI Variable: {}-{}".format(var_name, var_uuid))
                data_desc.append("* Data length: {} bytes".format(var_data_len))

        elif (pcr_index in (2, 4) and event_type == TcgEventType.EV_EFI_BOOT_SERVICES_APPLICATION) or \
                (pcr_index in (0, 2) and event_type == TcgEventType.EV_EFI_BOOT_SERVICES_DRIVER):
            # TCG_PCR_EVENT.digest = SHA-1 Hash of the normalized code from the loaded EFI Boot Services application
            # TCG_PCR_EVENT.Event[1] = EFI_IMAGE_LOAD_EVENT structure
            if len(event_data) >= 0x20:
                data_stream = BinStream(event_data)
                image_addr = data_stream.read_u64()
                image_len = data_stream.read_u64()
                image_linktime_addr = data_stream.read_u64()
                devpath_len = data_stream.read_u64()
                if len(event_data) == 0x20 + devpath_len:
                    digest_desc = "normalized code"
                    data_desc.append("* ImageLocationInMemory: {:#x}".format(image_addr))
                    data_desc.append("* ImageLengthInMemory: {:#x}".format(image_len))
                    data_desc.append("* (Image end in memory: {:#x})".format(image_addr + image_len))
                    data_desc.append("* ImageLinkTimeAddress: {:#x}".format(image_linktime_addr))
                    data_desc.append("* Device Path:")
                    while not data_stream.is_end():
                        # Decode a device path as EFI_DEVICE_PATH_PROTOCOL
                        devpath_type = data_stream.read_u8()
                        devpath_subtype = data_stream.read_u8()
                        devpath_len = data_stream.read_u16()
                        assert devpath_len >= 4
                        devpath_data = data_stream.read_bytes(devpath_len - 4)

                        dev_desc = None
                        if devpath_type == 0x01 and devpath_subtype == 0x01 and devpath_len == 6:
                            # Hardware Device Path / PCI Device Path SubType
                            pci_function, pci_device = struct.unpack('BB', devpath_data)
                            dev_desc = "HW-PCI dev {:#x} fun {:#x}".format(pci_device, pci_function)

                        if devpath_type == 0x02 and devpath_subtype == 0x01 and devpath_len == 0xc:
                            # ACPI Device Path / ACPI Device Path SubType
                            acpi_hid, acpi_uid = struct.unpack('<II', devpath_data)
                            dev_desc = "ACPI dev HID={:#x} UID={:#x}".format(acpi_hid, acpi_uid)
                            if (acpi_hid & 0xffff) == 0x41d0:  # 32-bit compressed EISA-type ID
                                dev_desc += " (compressed _HID=PNP{:04X}".format(acpi_hid >> 16)
                                if acpi_hid == 0x0a0341d0:
                                    dev_desc += " PCI host bridge"
                                dev_desc += ")"

                        if devpath_type == 0x03 and devpath_subtype == 0x05 and devpath_len == 6:
                            # Messaging Device Path / USB Device Path SubType
                            parent_port, interface = struct.unpack('BB', devpath_data)
                            dev_desc = "MSG-USB dev: parent port={}, interface={}".format(parent_port, interface)

                        if devpath_type == 0x03 and devpath_subtype == 0x12 and devpath_len == 0xa:
                            # Messaging Device Path / SATA Device Path SubType
                            hba_port, portmult_port, lun = struct.unpack('<HHH', devpath_data)
                            dev_desc = "MSG-SATA dev {:04x}/{:04x}/{:04x}".format(hba_port, portmult_port, lun)

                        if devpath_type == 0x03 and devpath_subtype == 0x17 and devpath_len == 0x10:
                            # Messaging Device Path / NvmExpress Namespace Device Path SubType
                            namespace_id, namespace_uuid = struct.unpack('<IQ', devpath_data)
                            dev_desc = "MSG-NVME dev ID={:#x}, UUID={:#x}".format(namespace_id, namespace_uuid)

                        if devpath_type == 0x04 and devpath_subtype == 0x01 and devpath_len == 0x2a:
                            # Media Device Path / Hard Drive Media Device Path SubType
                            part_num, part_start, part_size = struct.unpack('<IQQ', devpath_data[:0x14])
                            signature = devpath_data[0x14:0x24]
                            mbr_type, signature_type = struct.unpack('BB', devpath_data[0x24:])
                            dev_desc = "Hard Drive Media dev: part #{}, start={:#x}, size={:#x}, {}, sign<{}>={}".format(  # noqa
                                part_num, part_start, part_size,
                                {1: 'MBR', 2: 'GPT'}.get(mbr_type, "Unknown partition type {:#x}".format(mbr_type)),
                                signature_type, xx(signature))

                        if devpath_type == 0x04 and devpath_subtype == 0x04:
                            # Media Device Path / File Path Media Device Path SubType
                            file_path = devpath_data.decode('utf-16le', 'replace')
                            dev_desc = "File Path Media dev: {}".format(repr(file_path))

                        if devpath_type == 0x04 and devpath_subtype == 0x06 and devpath_len == 0x14:
                            # Media Device Path / PIWG Firmware File SubType
                            file_guid = uuid.UUID(bytes_le=devpath_data)
                            dev_desc = "Firmware file: {}".format(file_guid)

                        if devpath_type == 0x04 and devpath_subtype == 0x07 and devpath_len == 0x14:
                            # Media Device Path / PIWG Firmware Volume Device Path SubType
                            volume_device_guid = uuid.UUID(bytes_le=devpath_data)
                            dev_desc = "Firmware volume device: {}".format(volume_device_guid)

                        if devpath_type == 0x7f and devpath_subtype == 0xff and devpath_len == 4:
                            # End of Hardware Device Path
                            dev_desc = "End."

                        if dev_desc is None:
                            dev_desc = "??? {}".format(repr(devpath_data))

                        data_desc.append("  * {:02x}-{:02x}: {}".format(devpath_type, devpath_subtype, dev_desc))

        elif pcr_index == 0 and event_type == TcgEventType.EV_EFI_PLATFORM_FIRMWARE_BLOB:
            if len(event_data) == 0x10:
                platfw_physaddr, platfw_length = struct.unpack('<QQ', event_data)
                digest_desc = "Plat FW Blob"
                data_desc.append("* FW start: {:#x}".format(platfw_physaddr))
                data_desc.append("* FW length: {:#x} = {} kB".format(platfw_length, platfw_length / 1024.))
                data_desc.append("* (FW end: {:#x})".format(platfw_physaddr + platfw_length))

        elif pcr_index in (0, 1) and event_type == TcgEventType.EV_EFI_HANDOFF_TABLES:
            # TCG_PCR_EVENT.digest = SHA-1 Hash of system configuration tables
            # TCG_PCR_EVENT.Event[1] = EFI_HANDOFF_TABLE_POINTERS
            data_stream = BinStream(event_data)
            num_tables = data_stream.read_u64()
            if len(event_data) == 8 + num_tables * 0x18:
                digest_desc = "SystemTable.ConfigurationTable"
                while not data_stream.is_end():
                    # Decode a configuration table as EFI_CONFIGURATION_TABLE
                    tbl_guid = data_stream.read_uuid()
                    tbl_addr = data_stream.read_u64()
                    data_desc.append("* Configuration table for {} at {:#x}".format(tbl_guid, tbl_addr))

        if digest_desc is None:
            digest_desc = '?'
            for computed_digest in digests:
                computed_digest.matches(event_data, verbose=True)

        print("[PCR {:2d}] {:#x}={}".format(
            pcr_index,
            event_type, TcgEventType.describe(event_type),
        ))

        pcr_desc = PCR_DESCRIPTIONS.get(pcr_index)
        if pcr_desc:
            print("  Register: {}".format(pcr_desc))

        for computed_digest in digests:
            print("  {}".format(computed_digest.to_str(digest_desc)))

        # Dump the data
        for iline in range(0, len(event_data), 16):
            hexline = ''
            ascline = ''
            for i in range(16):
                if iline + i >= len(event_data):
                    hexline += '  '
                else:
                    val = event_data[iline + i]
                    hexline += '{:02x}'.format(val)
                    ascline += chr(val) if 32 <= val < 127 else '.'
                if i % 2:
                    hexline += ' '
            print("      {:04x}: {} {}".format(iline, hexline, ascline))

        # Display the description of the data
        for line in data_desc:
            print("  {}".format(line))

        print('')

    if not pcr_states:
        return

    for alg_id, pcrs in pcr_states.items():
        print("Final state of PCRs with {}:".format(TpmAlgId.get_name(alg_id)))
        for pcr_index, value in enumerate(pcrs):
            print("  PCR {:2d} = {}".format(pcr_index, xx(value)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode TPM's binary_bios_measurements")
    parser.add_argument('files', metavar="FILEPATH", nargs='*', type=Path,
                        help="files to analyze (eg. /sys/kernel/security/tpm0/binary_bios_measurements)")
    args = parser.parse_args(argv)

    if args.files:
        for input_path in args.files:
            analyze_tpm_binary_bios_measurements(input_path, fail_if_denied=True)
    else:
        if platform.system() == 'Windows':
            input_files = list(Path('C:\\Windows\\Logs\\MeasuredBoot').glob('*.log'))
        else:
            input_files = list(Path('/sys/kernel/security/').glob('tpm*/binary_bios_measurements'))

        if not input_files:
            print("Unable to find a TPM binary measurement file")
            return
        for input_path in input_files:
            analyze_tpm_binary_bios_measurements(input_path, fail_if_denied=False)


if __name__ == '__main__':
    main()
