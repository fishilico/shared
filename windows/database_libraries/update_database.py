#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2020 Nicolas Iooss
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
"""Update the database of files by parsing a file

@author: Nicolas Iooss
@license: MIT
"""
import argparse
import binascii
import collections
import datetime
import json
import logging
from pathlib import Path
import re
import sys
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent))
import pe_structs  # noqa


BASE_DIR_PATH = Path(__file__).parent


# pylint: disable=invalid-name
logger = logging.getLogger(__name__)


def version_str_sortkey(vers_str: str) -> Tuple[List[int], List[int]]:
    """Sort version strings according to the numeric order"""
    parts = vers_str.split('_')
    return ([int(x) for x in parts[0].split('.')], [int(x, 16) for x in parts[1:]])


class Database:
    """Database of libraries"""
    def __init__(self):
        self.base_dir_path = BASE_DIR_PATH
        self.libraries = {}

        # Load files
        for file_path in self.base_dir_path.glob('*/*.db.json'):
            with file_path.open('r') as stream:
                data = json.load(stream)
                self.merge_data(data)

        # Find existing library names
        self.existing_names = set()
        for name_and_arch in self.libraries.keys():
            name = name_and_arch.rsplit('.', 1)[0]
            self.existing_names.add(name)

        logger.info("Loaded data about %d libraries (%d different names)",
                    len(self.libraries), len(self.existing_names))

    def merge_data(self, data):
        """Merge a library->key->value dictionary into the database"""
        for name, lib_data in data.items():
            if name not in self.libraries:
                # Ensure that the name is right
                if not re.match(r'^[-0-9a-z._]+\.(dll|exe|sys)\.([a-z0-9_]+)$', name):
                    raise ValueError("Invalid library name {}".format(repr(name)))
                self.libraries[name] = {}

            # Merge the incoming data
            for key, value in lib_data.items():
                if key not in self.libraries[name]:
                    # Simple case: a new key is added
                    # Ensure that the name of the key is right
                    if not re.match(r'^[a-z]+$', key):
                        raise ValueError("Invalid key name {} for {}".format(repr(key), name))
                    self.libraries[name][key] = {}

                # If a new version is added, replace it, keeping the older ones
                if key == 'versions':
                    self.libraries[name][key].update(value)
                    self.libraries[name][key] = collections.OrderedDict(sorted(
                        self.libraries[name][key].items(),
                        key=lambda kv: (version_str_sortkey(kv[0]), kv[1])))
                    continue

                # If new exports are added, update the versions
                if key == 'exports':
                    for dll_name, export_data in value.items():
                        if dll_name not in self.libraries[name][key]:
                            self.libraries[name][key][dll_name] = {}

                        for fct_name, fct_data in export_data.items():
                            if fct_name not in self.libraries[name][key][dll_name]:
                                self.libraries[name][key][dll_name][fct_name] = fct_data
                                continue
                            for fct_ord, fct_versions in fct_data.items():
                                if fct_ord not in self.libraries[name][key][dll_name][fct_name]:
                                    self.libraries[name][key][dll_name][fct_name][fct_ord] = fct_versions
                                    continue
                                self.libraries[name][key][dll_name][fct_name][fct_ord] = sorted(
                                    set(self.libraries[name][key][dll_name][fct_name][fct_ord] + fct_versions),
                                    key=version_str_sortkey)
                    continue

                # If new syscalls are added, update the versions
                if key == 'syscalls':
                    for fct_name, fct_data in value.items():
                        if fct_name not in self.libraries[name][key]:
                            self.libraries[name][key][fct_name] = {}
                        for sysnum, fct_versions in fct_data.items():
                            if isinstance(sysnum, str):
                                # Force using integer as syscall numbers, even when JSON saves them as strings
                                sysnum = int(sysnum)
                            if sysnum not in self.libraries[name][key][fct_name]:
                                self.libraries[name][key][fct_name][sysnum] = []
                            self.libraries[name][key][fct_name][sysnum] = sorted(
                                set(self.libraries[name][key][fct_name][sysnum] + fct_versions),
                                key=version_str_sortkey)
                    continue

                raise NotImplementedError("Unable to merge {}/{} into the database".format(name, key))

    def save(self):
        """Split the database into JSON files"""
        logger.info("Saving data about %d libraries", len(self.libraries))
        for name_and_arch, lib_data in self.libraries.items():
            name = name_and_arch.rsplit('.', 1)[0]
            dir_path = BASE_DIR_PATH / "{}.db".format(name)
            dir_path.mkdir(exist_ok=True)
            for key, value in lib_data.items():
                # Sort the value
                if key == 'versions':
                    value = collections.OrderedDict(sorted(
                        value.items(),
                        key=lambda kv: (version_str_sortkey(kv[0]), kv[1])))
                elif key == 'exports':
                    value = collections.OrderedDict(sorted(
                        (dll_name, collections.OrderedDict(sorted(
                            (fct_name, collections.OrderedDict(sorted(
                                # Filter the versions in order to only include the first 3 numbers
                                # (Major.Minor.Build), not the extra part of updates.
                                (fct_ord, sorted(
                                    set('.'.join(ver.split('.', 3)[:3]) for ver in fct_versions),
                                    key=version_str_sortkey
                                ))
                                for fct_ord, fct_versions in fct_data.items()
                            )))
                            for fct_name, fct_data in export_data.items()
                        )))
                        for dll_name, export_data in value.items()
                    ))
                elif key == 'syscalls':
                    value = collections.OrderedDict(sorted(
                        (fct_name, collections.OrderedDict(sorted(
                            (sysnum, sorted(
                                set('.'.join(ver.split('.', 3)[:3]) for ver in fct_versions),
                                key=version_str_sortkey
                            ))
                            for sysnum, fct_versions in fct_data.items()
                        )))
                        for fct_name, fct_data in value.items()
                    ))
                else:
                    raise NotImplementedError("Sorting of {} is not implemented".format(repr(key)))

                save_path = dir_path / "{}_{}.db.json".format(name_and_arch, key)
                temp_save_path = dir_path / "{}_{}.db.json.temp".format(name_and_arch, key)
                with temp_save_path.open('w') as stream:
                    json.dump({name_and_arch: {key: value}}, stream, indent=2)
                temp_save_path.replace(save_path)

    def analyze_file(self, file_path: Path, only_existing: bool = False, recursive_dir: bool = False) -> bool:
        """Analyze a file, depending on its type"""
        if file_path.is_dir():
            self.analyze_directory(file_path, recursive_dir=recursive_dir)
            return True

        # Load the beginning of the file, in order to find out its type
        try:
            with file_path.open('rb') as stream:
                beginning = stream.read(4096)
        except PermissionError:
            logger.warning("Permission denied for file %s", file_path)
            return False

        if beginning.startswith(b'MZ'):
            # Load a PE header to check its magic numbers
            mzdos_header: pe_structs.struct_image_dos_header = \
                pe_structs.struct_image_dos_header.from_buffer_copy(beginning)  # type: ignore
            peheader_offset: int = mzdos_header.e_lfanew
            if beginning[peheader_offset:peheader_offset + 4] == b'PE\0\0':
                self.analyze_pe_file(file_path, only_existing=only_existing)
                return True

        if not only_existing:
            logger.error("Unexpected file type for %s", file_path)
        return False

    def analyze_directory(self, file_path: Path, recursive_dir: bool = False):
        """Analyze all files in a directory"""
        try:
            children = list(file_path.iterdir())
        except PermissionError:
            logger.warning("Permission denied for directory %s", file_path)
            return

        for child_path in children:
            try:
                if child_path.is_block_device() or child_path.is_char_device() or \
                        child_path.is_fifo() or child_path.is_socket() or child_path.is_symlink():
                    # Ignore special files
                    continue
            except PermissionError:
                logger.warning("Permission denied for stat on %s", child_path)
                continue

            if child_path.is_dir():
                if recursive_dir:
                    self.analyze_directory(child_path, recursive_dir=recursive_dir)
                continue

            # Ignore files with an extension which have no chance to be interesting
            if child_path.suffix.upper() in ('.DLL', '.EXE'):
                pass
            elif child_path.suffix.upper() == '.SYS':
                # Grab win32k*.sys
                if child_path.name.upper().startswith('WIN32K'):
                    pass
                else:
                    continue
            else:
                continue

            # Restrict adding files to those which already exist in the database
            self.analyze_file(child_path, only_existing=True, recursive_dir=recursive_dir)

    def analyze_pe_file(self, file_path: Path, only_existing):
        """Analyze a PE file"""
        try:
            pe_file = pe_structs.PEFile(file_path)
        except (AssertionError, KeyError, NotImplementedError, TypeError, ValueError) as exc:
            logger.error("Error while reading PE file: %s", file_path)
            logger.error("... Exception: %s", exc)
            return

        # If there is no version resource, ignore the file
        if not pe_file.resource_version_info:
            logger.debug("Ignoring PE file without version information: %s", file_path)
            return

        # If the file if from Wine, ignore it
        legal_copyright = pe_file.resource_version_info.string_file_info.get('LegalCopyright', '')
        if 'the Wine project authors' in legal_copyright:
            logger.debug("Ignoring Wine file %s", file_path)
            return

        # If there is no PE file name, ignore the file
        if not pe_file.pe_file_name:
            logger.debug("Ignoring PE file without a proper name: %s", file_path)
            return

        # Use the PE file name and the architecture to index the data
        try:
            arch = pe_structs.MACHINE_TYPE_NAME[pe_file.pe_header.FileHeader.Machine]
        except KeyError:
            logger.error("Unknown machine type %#x in %s", pe_file.pe_header.FileHeader.Machine, file_path)
            return
        name_and_arch = "{}.{}".format(pe_file.pe_file_name.lower(), arch)

        if only_existing and pe_file.pe_file_name.lower() not in self.existing_names:
            # Ignore files that do not already exist in the database
            logger.debug("Ignoring new file %s from %s", name_and_arch, file_path)
            return

        # Gather information about this version of the PE file
        # As the file version may conflict for example between kernel32.dll and OneCore,
        # combine it with the timestamp and the size of image and of the file,
        # in hope everything goes well and this tuple is really unique.
        file_version = pe_file.resource_version_info.file_version
        timestamp = pe_file.pe_header.FileHeader.TimeDateStamp
        size_of_image = pe_file.pe_header.OptionalHeader.SizeOfImage
        file_vers_ts_size = '{}_{:08x}_{:x}_{:x}'.format(
            file_version, timestamp, size_of_image, len(pe_file.file_content))
        version_info = collections.OrderedDict((
            ('pe_header', collections.OrderedDict((
                ('machine', pe_file.pe_header.FileHeader.Machine),
                ('timestamp', timestamp),
                ('timestamp_iso', str(datetime.datetime.utcfromtimestamp(timestamp))),
                ('coff_characteristics', pe_file.pe_header.FileHeader.Characteristics),
                ('linker_version', '{}.{}'.format(
                    pe_file.pe_header.OptionalHeader.MajorLinkerVersion,
                    pe_file.pe_header.OptionalHeader.MinorLinkerVersion)),
                ('image_base', pe_file.pe_header.OptionalHeader.ImageBase),
                ('size_of_image', size_of_image),
                ('subsystem', pe_file.pe_header.OptionalHeader.Subsystem),
                ('dll_characteristics', pe_file.pe_header.OptionalHeader.DllCharacteristics),
            ))),
            ('file_size', len(pe_file.file_content)),
            ('file_version', file_version),
            ('product_version', pe_file.resource_version_info.product_version),
            ('string_info', pe_file.resource_version_info.string_file_info),
        ))

        if pe_file.signatures:
            version_info['authenticode'] = []
            for signature in pe_file.signatures:
                sign_info = collections.OrderedDict((
                    ('digest_alg', signature.data.content_info.content.digest_alg),
                    ('digest', binascii.hexlify(signature.data.content_info.content.digest).decode('ascii')),
                    ('signer_infos', collections.OrderedDict((
                        ('issuer', signature.data.signer_info.issuer),
                        ('serial_number', signature.data.signer_info.serial_number),
                        ('digest_enc_alg', signature.data.signer_info.digest_enc_alg),
                    ))),
                ))

                # Record the timestamp counter sign attribute, if provided
                tscs_attr = signature.data.signer_info.unauthenticated_attrs.get('timestampCounterSign')
                if tscs_attr is not None:
                    timestamp = tscs_attr.data.content_info.content.gen_time
                    timestamp_seconds = (timestamp - datetime.datetime(1970, 1, 1)).total_seconds()
                    sign_info['timestamp_counter_sign'] = collections.OrderedDict((
                        ('timestamp', timestamp_seconds),
                        ('timestamp_iso', str(timestamp)),
                        ('signer_infos', collections.OrderedDict((
                            ('issuer', tscs_attr.data.signer_info.issuer),
                            ('serial_number', tscs_attr.data.signer_info.serial_number),
                            ('digest_enc_alg', tscs_attr.data.signer_info.digest_enc_alg),
                        ))),
                    ))
                version_info['authenticode'].append(sign_info)

        if pe_file.export_dll_name:
            version_info['export_dll_name'] = pe_file.export_dll_name

        if pe_file.debug_codeview_guid is not None:
            version_info['debug_codeview'] = collections.OrderedDict((
                ('guid', str(pe_file.debug_codeview_guid)),
                ('age', pe_file.debug_codeview_age),
                ('path', pe_file.debug_codeview_path),
            ))

        if pe_file.debug_codeview_timestamp is not None:
            version_info['debug_codeview_timed'] = collections.OrderedDict((
                ('timestamp', pe_file.debug_codeview_timestamp),
                ('timestamp_iso', str(datetime.datetime.utcfromtimestamp(pe_file.debug_codeview_timestamp))),
                ('age', pe_file.debug_codeview_age),
                ('path', pe_file.debug_codeview_path),
            ))

        if pe_file.debug_repro_data is not None:
            if pe_file.debug_repro_data == b'':
                # Reproducible build, but no debug-specific information
                version_info['debug_reproducible'] = {}
            else:
                version_info['debug_reproducible'] = collections.OrderedDict((
                    ('guid', str(pe_file.debug_repro_guid)),
                    ('unknown', binascii.hexlify(pe_file.debug_repro_unknown).decode('ascii')),
                    ('timestamp', pe_file.debug_repro_timestamp),
                ))

        if pe_file.resource_version_info.fixed.dwFileFlags:
            version_info['version_info_file_flags'] = [
                pe_file.resource_version_info.fixed.dwFileFlags,
                pe_file.resource_version_info.fixed.dwFileFlagsMask]

        self.merge_data({
            name_and_arch: {
                'versions': {
                    file_vers_ts_size: version_info
                }
            }
        })

        if pe_file.export_dll_name and pe_file.exported_functions:
            # There are exported functions
            functions_and_version = collections.OrderedDict()
            for name in sorted(pe_file.exported_functions.keys()):
                fct_ord = pe_file.exported_functions_ord[name]
                target = pe_file.exported_functions[name]
                if isinstance(target, int):
                    # Normal export
                    target_desc = str(fct_ord)
                else:
                    # Forwarder export entry
                    assert isinstance(target, str)
                    target_desc = '{} {}'.format(fct_ord, target)
                functions_and_version[name] = {target_desc: [file_vers_ts_size]}

            self.merge_data({
                name_and_arch: {
                    'exports': {
                        pe_file.export_dll_name: functions_and_version,
                    }
                }
            })

        if pe_file.syscall_stubs:
            # Save the syscall stubs
            syscalls = collections.OrderedDict()
            for name, sysnum in sorted(pe_file.syscall_stubs.items()):
                syscalls[name] = {
                    sysnum: [file_vers_ts_size],
                }
            self.merge_data({
                name_and_arch: {
                    'syscalls': syscalls,
                }
            })


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Update the database")
    parser.add_argument('files', metavar="FILE", nargs='+', type=Path,  # type: ignore
                        help="Files to analyze")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-r', '--recursive', action='store_true',
                        help="recurse into directories")
    args = parser.parse_args(argv)
    arg_files = args.files  # type: List[Path]
    arg_debug = args.debug  # type: bool
    arg_recursive = args.recursive  # type: bool

    logging.basicConfig(format='[%(levelname)s] %(message)s',
                        level=logging.DEBUG if arg_debug else logging.INFO)

    db = Database()

    for file_path in arg_files:
        if not db.analyze_file(file_path, recursive_dir=arg_recursive):
            return 1

    db.save()
    return 0


if __name__ == '__main__':
    sys.exit(main())
