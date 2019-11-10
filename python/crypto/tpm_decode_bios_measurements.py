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
"""Decode BIOS measurements from TPM 1 event log

Linux exposes this event log file in securityfs:
/sys/kernel/security/tpm0/binary_bios_measurements.
The Linux kernel module that exposes it has its source code on
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/char/tpm/eventlog/tpm2.c?h=v5.1

The events are specified in https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/
"""
import argparse
import binascii
import hashlib
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


def xx(data):
    """One-line hexadecimal representation of binary data"""
    return binascii.hexlify(data).decode('ascii')


class BinStream:
    """Binary stream of data, which is parsed"""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def is_end(self):
        """Is the end of stream reached?"""
        return self.pos >= len(self.data)

    def read_bytes(self, count):
        assert count >= 0
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

    pcr_states = []

    print("{}:".format(bin_path))
    while not stream.is_end():
        # Read a tdTCG_PCR_EVENT structure
        pcr_index = stream.read_u32()
        event_type = stream.read_u32()
        digest = stream.read_bytes(20)  # SHA-1 digest
        event_size = stream.read_u32()
        event_data = stream.read_bytes(event_size)

        # Extend existing PCRs
        if len(pcr_states) <= pcr_index < 256:
            pcr_states += [bytes(20)] * (pcr_index + 1 - len(pcr_states))
        pcr_states[pcr_index] = hashlib.sha1(pcr_states[pcr_index] + digest).digest()

        computed = hashlib.sha1(event_data).digest()
        digest_desc = None
        data_desc = []
        if computed == digest:
            digest_desc = "SHA1(data)"
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
                digest_desc = "SHA1(ACPI DATA)"
            elif len(event_data) == 0x10:
                post_physaddr, post_length = struct.unpack('<QQ', event_data)
                digest_desc = "SHA1(POST code)"
                data_desc.append("* POST start: {:#x}".format(post_physaddr))
                data_desc.append("* POST length: {:#x} = {} kB".format(post_length, post_length / 1024.))
                data_desc.append("* (POST end: {:#x})".format(post_physaddr + post_length))

        elif pcr_index == 0 and event_type == TcgEventType.EV_S_CRTM_CONTENTS:
            # TCG_PCR_EVENT.digest = SHA-1 Hash of the CRTM content
            # TCG_PCR_EVENT.Event[1] = EFI_PLATFORM_FIRMWARE_BLOB structure (base + length)
            if len(event_data) == 0x10:
                crtm_physaddr, crtm_length = struct.unpack('<QQ', event_data)
                digest_desc = "SHA1(CRTM Contents)"
                data_desc.append("* CRTM start: {:#x}".format(crtm_physaddr))
                data_desc.append("* CRTM length: {:#x} = {} kB".format(crtm_length, crtm_length / 1024.))
                data_desc.append("* (CRTM end: {:#x})".format(crtm_physaddr + crtm_length))

        elif pcr_index == 5 and event_type == TcgEventType.EV_EFI_VARIABLE_BOOT:
            # EFI_VARIABLE_DATA structure => compute name for /sys/firmware/efi/efivars/
            if len(event_data) >= 0x20:
                digest_desc = "SHA1(Boot variables)"
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
                    digest_desc = "SHA1(normalized code)"
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

        elif pcr_index == 0and event_type == TcgEventType.EV_EFI_PLATFORM_FIRMWARE_BLOB:
            if len(event_data) == 0x10:
                platfw_physaddr, platfw_length = struct.unpack('<QQ', event_data)
                digest_desc = "SHA1(Plat FW Blob)"
                data_desc.append("* FW start: {:#x}".format(platfw_physaddr))
                data_desc.append("* FW length: {:#x} = {} kB".format(platfw_length, platfw_length / 1024.))
                data_desc.append("* (FW end: {:#x})".format(platfw_physaddr + platfw_length))

        elif pcr_index in (0, 1) and event_type == TcgEventType.EV_EFI_HANDOFF_TABLES:
            # TCG_PCR_EVENT.digest = SHA-1 Hash of system configuration tables
            # TCG_PCR_EVENT.Event[1] = EFI_HANDOFF_TABLE_POINTERS
            data_stream = BinStream(event_data)
            num_tables = data_stream.read_u64()
            if len(event_data) == 8 + num_tables * 0x18:
                digest_desc = "SHA1(SystemTable.ConfigurationTable)"
                while not data_stream.is_end():
                    # Decode a configuration table as EFI_CONFIGURATION_TABLE
                    tbl_guid = data_stream.read_uuid()
                    tbl_addr = data_stream.read_u64()
                    data_desc.append("* Configuration table for {} at {:#x}".format(tbl_guid, tbl_addr))

        if digest_desc is None:
            digest_desc = '?'
            print("Warning: unexpected digest, computed {}".format(xx(computed)))

        print("[PCR {:2d}] {:#x}={}, {}={}".format(
            pcr_index,
            event_type, TcgEventType.describe(event_type),
            digest_desc, xx(digest),
        ))
        pcr_desc = PCR_DESCRIPTIONS.get(pcr_index)
        if pcr_desc:
            print("  Register: {}".format(pcr_desc))

        # Dump the data
        for iline in range(0, len(event_data), 16):
            hexline = ''
            ascline = ''
            for i in range(16):
                if iline + i >= len(event_data):
                    hexline += '  '
                else:
                    # pylint: disable=invalid-name
                    x = event_data[iline + i]
                    hexline += '{:02x}'.format(x)
                    ascline += chr(x) if 32 <= x < 127 else '.'
                if i % 2:
                    hexline += ' '
            print("  {:04x}: {} {}".format(iline, hexline, ascline))

        # Display the description of the data
        for line in data_desc:
            print("  {}".format(line))

        print('')

    if not pcr_states:
        return
    print("Final state of PCRs:")
    for pcr_index, value in enumerate(pcr_states):
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
        input_files = list(Path('/sys/kernel/security/').glob('tpm*/binary_bios_measurements'))
        if not input_files:
            print("Unable to find a TPM binary measurement file")
            return
        for input_path in input_files:
            analyze_tpm_binary_bios_measurements(input_path, fail_if_denied=False)


if __name__ == '__main__':
    main()
