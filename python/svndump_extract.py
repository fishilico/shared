#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2023 Nicolas Iooss
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
"""Extract the result of "svnadmin dump" of a Subversion repository

"svnadmin dump" can be used to export the content of a Subversion repository in
a file which format is documented on
https://svn.apache.org/repos/asf/subversion/trunk/notes/dump-load-format.txt

A dump can be loaded with "svnadmin load", as documented on
https://www.saas-secure.com/svn-hosting/svn-dump-restore.html

This script has been tested with the dumps from the Subversion repository:
https://svn.apache.org/repos/asf/subversion/trunk/subversion/tests/cmdline/svndumpfilter_tests_data/

Dump format version 3 introduced deltas: before, the full files were written to
the dump file. Each file is a diff parsed by libsvn_diff, with a 4-byte header
giving the version ("SVN\x01" is version 1):
https://svn.apache.org/viewvc/subversion/tags/1.14.2/subversion/libsvn_delta/svndiff.c?view=markup
"""
import argparse
import hashlib
import sys
from pathlib import Path
from typing import BinaryIO, Dict, FrozenSet, List, Optional, Tuple


class EOFReached(Exception):
    pass


# https://svn.apache.org/viewvc/subversion/tags/1.14.2/subversion/libsvn_delta/delta.h?view=markup#l45
SVN_DELTA_WINDOW_SIZE = 102400

# https://svn.apache.org/viewvc/subversion/tags/1.14.2/subversion/include/private/svn_subr_private.h?view=markup#l487
SVN__MAX_ENCODED_UINT_LEN = 10

# https://svn.apache.org/viewvc/subversion/tags/1.14.2/subversion/libsvn_delta/svndiff.c?view=markup#l70
MAX_INSTRUCTION_LEN = 2 * SVN__MAX_ENCODED_UINT_LEN + 1
MAX_INSTRUCTION_SECTION_LEN = SVN_DELTA_WINDOW_SIZE * MAX_INSTRUCTION_LEN

KNOWN_SVN_NODE_HEADERS: FrozenSet[str] = frozenset(
    (
        "Content-length",
        "Node-action",
        "Node-copyfrom-path",
        "Node-copyfrom-rev",
        "Node-kind",
        "Node-path",
        "Prop-content-length",
        "Prop-delta",
        "Text-content-length",
        "Text-content-md5",
        "Text-content-sha1",
        "Text-copy-source-md5",
        "Text-copy-source-sha1",
        "Text-delta",
        "Text-delta-base-md5",
        "Text-delta-base-sha1",
    )
)


def decode_var_uint(buffer: bytes, offset: int) -> Tuple[int, int]:
    """Decode a variable-size unsigned int and return it with the new offset

    cf. Function svn__decode_uint in
    https://svn.apache.org/viewvc/subversion/tags/1.14.2/subversion/libsvn_subr/encode.c?view=markup#l64
    """
    assert 0 <= offset < len(buffer)
    value = 0
    initial_offset = offset
    while True:
        cur = buffer[offset]
        offset += 1
        assert offset - initial_offset <= SVN__MAX_ENCODED_UINT_LEN
        if cur < 0x80:
            value = (value << 7) | cur
            return value, offset
        value = (value << 7) | (cur & 0x7F)


def extract_from_svndiff(text: bytes, verbose: bool = False) -> Optional[bytes]:
    """Extract some content from a delta"""
    if len(text) < 4 + 5:
        if text == b"SVN\x00":
            # This is an empty file
            return b""
        raise ValueError("Text-delta present a short text {text!r}")

    # Parse svndiff format
    svndiff_magic = text[:4]
    if svndiff_magic != b"SVN\x00":  # Version 0
        raise NotImplementedError(f"Unsupported svndiff version {svndiff_magic!r}")

    offset = 4
    new_text_parts = []
    while offset < len(text):
        sview_offset, offset = decode_var_uint(text, offset)
        sview_len, offset = decode_var_uint(text, offset)
        tview_len, offset = decode_var_uint(text, offset)
        inslen, offset = decode_var_uint(text, offset)
        newlen, offset = decode_var_uint(text, offset)
        assert sview_len <= SVN_DELTA_WINDOW_SIZE
        assert tview_len <= SVN_DELTA_WINDOW_SIZE
        assert newlen <= SVN_DELTA_WINDOW_SIZE + SVN__MAX_ENCODED_UINT_LEN
        assert inslen <= MAX_INSTRUCTION_SECTION_LEN

        # If there is some source, this is not a new file
        if verbose:
            print(
                f"      svn-diff: sview@{sview_offset}[{sview_len}], tview[{tview_len}] inst[{inslen}] new[{newlen}] {text[offset:offset + 20]!r}"  # noqa
            )
        if sview_len != 0:
            return None

        # Decode instructions
        # Actions from
        # https://svn.apache.org/viewvc/subversion/tags/1.14.2/subversion/include/svn_delta.h?view=markup#l115
        #     0 is svn_txdelta_source
        #     1 is svn_txdelta_target
        #     2 is svn_txdelta_new
        instructions: List[Tuple[int, int, int]] = []
        inst_base_offset = offset
        while offset < inst_base_offset + inslen:
            c = text[offset]
            offset += 1
            action = c >> 6
            assert 0 <= action <= 3
            if action == 3:
                raise ValueError("Unsupported svndiff action 3")
            op_length = c & 0x3F
            if op_length == 0:
                op_length, offset = decode_var_uint(text, offset)
            if action == 0 or action == 1:
                op_offset, offset = decode_var_uint(text, offset)
            else:
                op_offset = 0

            if 0:
                # DEBUG
                print(
                    f"[{offset - inst_base_offset:3}/{inslen:3}] {action} {op_length:4} {op_offset:4}, next {text[offset:offset + 8].hex()}..."  # noqa
                )
            instructions.append((action, op_length, op_offset))

        if inst_base_offset + inslen != offset:
            raise ValueError(
                f"Invalid offset {offset} after instruction {inst_base_offset} + {inslen} = {inst_base_offset + inslen}"
            )

        if len(instructions) == 1 and instructions[0] == (2, newlen, 0):
            assert tview_len == newlen
            # add the part and continue
            new_offset = offset + newlen
            assert len(text) >= new_offset
            new_text_parts.append(text[offset:new_offset])
            offset = new_offset
            continue

        # Early return
        return None

    # Join all new parts together
    assert offset == len(text)
    return b"".join(new_text_parts)


class SvnDumpStream:
    """Stream of a Subversion dump file"""

    def __init__(self, stream: BinaryIO, verbose: bool = False) -> None:
        self.stream = stream
        self.verbose = verbose

        # Internal buffer
        self.buffer = b""
        self.reached_eof = False

        self.svn_fs_dump_format_version: Optional[int] = None
        self.current_revision: Optional[int] = None

    def bufferize_some_bytes(self, size: int = 4096) -> bytes:
        """Read some bytes to the internal buffer, detecting end of file"""
        if self.reached_eof:
            assert not self.buffer
            raise EOFReached
        new_data = self.stream.read(size)
        if not new_data:
            self.reached_eof = True
            raise EOFReached
        self.buffer += new_data
        return new_data

    def peek_next_char(self) -> str:
        """Peek the next character without consuming it.

        Return an empty string if the end of stream was reached
        """
        if self.reached_eof:
            assert not self.buffer
            return ""
        if not self.buffer:
            try:
                self.bufferize_some_bytes()
            except EOFReached:
                assert not self.buffer
                return ""
        return self.buffer[:1].decode("utf-8")

    def read_line(self) -> str:
        """Read a line ending with \n"""
        if b"\n" not in self.buffer:
            while b"\n" not in self.bufferize_some_bytes():
                pass
        line, newbuf = self.buffer.split(b"\n", 1)
        self.buffer = newbuf
        # print(f"\033[37m<Line: {line!r}\033[m")
        return line.decode("utf-8")

    def read_exact(self, size: int) -> bytes:
        """Read this exact amount of bytes from the stream"""
        if size == 0:
            return b""
        assert size > 0
        while len(self.buffer) < size:
            self.bufferize_some_bytes(size - len(self.buffer))
        assert len(self.buffer) >= size
        result = self.buffer[:size]
        self.buffer = self.buffer[size:]
        # print(f"\033[37m<Exact[{size}]: {result[:1000]!r}...\033[m")
        return result

    def put_back(self, data: bytes) -> None:
        """Put some data back into the buffer"""
        self.buffer = data + self.buffer
        self.reached_eof = False

    def read_svn_dump_header(self) -> None:
        """Read a svn dump header"""
        line = self.read_line()
        if not line.startswith("SVN-fs-dump-format-version: "):
            raise ValueError(f"Unexpected SVN fs dump format version line: {line!r}")
        self.svn_fs_dump_format_version = int(line.split(": ", 1)[1])
        line = self.read_line()
        if line != "":
            raise ValueError(f"Unexpected non-empty line: {line!r}")
        line = self.read_line()
        if not line.startswith("UUID: "):
            raise ValueError(f"Unexpected UUID line: {line!r}")
        line = self.read_line()
        if line != "":
            raise ValueError(f"Unexpected non-empty line: {line!r}")

        if self.verbose:
            print(f"SVN dump format version {self.svn_fs_dump_format_version}")

    def read_revision(self) -> None:
        """Read a SVN revision"""
        line = self.read_line()
        if not line.startswith("Revision-number: "):
            raise ValueError(f"Unexpected Revision-number line: {line!r}")
        rev_number = int(line.split(": ", 1)[1])

        line = self.read_line()
        if not line.startswith("Prop-content-length: "):
            raise ValueError(f"Unexpected Prop-content-length line: {line!r}")
        prop_content_length = int(line.split(": ", 1)[1])

        line = self.read_line()
        if not line.startswith("Content-length: "):
            raise ValueError(f"Unexpected Content-length line: {line!r}")
        content_length = int(line.split(": ", 1)[1])

        line = self.read_line()
        if line != "":
            raise ValueError(f"Unexpected non-empty line: {line!r}")

        if not (0 <= prop_content_length <= content_length):
            raise ValueError(
                f"Invalid Prop-content-length {prop_content_length} for {content_length} for revision {rev_number}"
            )
        text_content_length = content_length - prop_content_length

        props = self.read_exact(prop_content_length)
        if prop_content_length and not props.endswith(b"PROPS-END\n"):
            # Sometimes there are differences
            try:
                end_index = props.rindex(b"PROPS-END\n") + len(b"PROPS-END\n")
            except ValueError:
                raise ValueError(f"Invalid revision {rev_number} props not ending with PROPS-END: {props!r}")
            print(
                f"WARNING: props of revision {rev_number} has length {end_index} instead of {prop_content_length}",
                file=sys.stderr,
            )
            self.put_back(props[end_index:])
            props = props[:end_index]
        text = self.read_exact(text_content_length)

        line = self.read_line()
        if line != "":
            raise ValueError(f"Unexpected non-empty line: {line!r}")

        if self.verbose:
            print(f"Revision {rev_number}: Props {props!r}, {text!r}")
        self.current_revision = rev_number

    def read_node(self, outdir: Optional[Path] = None) -> None:
        """Read a SVN Node and optionaly extract it to the output directory"""
        # Decode headers
        headers: Dict[str, str] = {}
        line = self.read_line()
        while line != "":
            key, value = line.split(": ")
            if key not in KNOWN_SVN_NODE_HEADERS:
                raise ValueError(f"Unknown node header key in {line!r}")
            if key in headers:
                raise ValueError(f"Duplicate header key {key!r}")
            headers[key] = value
            line = self.read_line()

        node_path = headers["Node-path"]
        prop_content_length = int(headers.get("Prop-content-length", "0"))
        text_content_length = int(headers.get("Text-content-length", "0"))
        content_length = int(headers.get("Content-length", "0"))

        if not (0 <= prop_content_length <= content_length):
            raise ValueError(
                f"Invalid Prop-content-length {prop_content_length} for {content_length} for node {node_path!r}"
            )
        if not (0 <= text_content_length <= content_length):
            raise ValueError(
                f"Invalid Text-content-length {text_content_length} for {content_length} for node {node_path!r}"
            )
        if prop_content_length + text_content_length != content_length:
            raise ValueError(
                f"Invalid Content-length {content_length} != {prop_content_length} + {text_content_length} for node {node_path!r}"  # noqa
            )

        props = self.read_exact(prop_content_length)
        if prop_content_length and not props.endswith(b"PROPS-END\n"):
            raise ValueError(f"Invalid node props not ending with PROPS-END: {props!r}")
        text = self.read_exact(text_content_length)
        # Remove optional empty lines
        while self.peek_next_char() == "\n":
            line = self.read_line()
            assert line == ""

        if self.verbose:
            print(f"  Node {node_path!r}")
            for key, value in headers.items():
                print(f"    {key}: {value}")
            if prop_content_length:
                print(f"    Props[{prop_content_length}]: {props!r}")
            if text_content_length:
                print(f"    Text[{text_content_length}]: {text[:100]!r}")

        is_delta = headers.get("Text-delta")
        if is_delta:
            if is_delta != "true":
                raise ValueError(f"Unexpected Text-delta value {is_delta!r}")
            if not text:
                raise ValueError("Text-delta header present without any text")
            new_text = extract_from_svndiff(text, verbose=self.verbose)
            if new_text is not None:
                text = new_text
                is_delta = None
                if self.verbose:
                    print(f"      extracted[{len(text)}]: {text[:100]!r}")

        # Validate the digest, if it is not a delta
        if is_delta is None:
            text_md5 = headers.get("Text-content-md5")
            text_sha1 = headers.get("Text-content-sha1")
            if text and not (text_md5 or text_sha1):
                print(f"WARNING: Missing content hash for node with text, {node_path!r}", file=sys.stderr)
            if text_md5:
                computed_md5 = hashlib.md5(text).hexdigest()
                if computed_md5 != text_md5:
                    raise ValueError(f"Mismatched MD5 digest: {computed_md5} != {text_md5}")
            if text_sha1:
                computed_sha1 = hashlib.sha1(text).hexdigest()
                if computed_sha1 != text_sha1:
                    raise ValueError(f"Mismatched SHA1 digest: {computed_sha1} != {text_sha1}")

        # Extraction
        if text and outdir is not None:
            assert self.current_revision is not None
            out_file = (outdir / (node_path + f"._.r{self.current_revision}")).resolve()
            if not out_file.is_relative_to(outdir):
                raise RuntimeError(f"Security issue: extracting {node_path!r} outside of directory {outdir}")
            if out_file.exists():
                raise RuntimeError(f"Refusing to overwrite existing file {out_file}")
            if self.verbose:
                print(f"    extract to {out_file}")
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with out_file.open("xb") as fout:
                fout.write(text)

    def decode_svn_dump(self, outdir: Optional[Path] = None) -> None:
        """Decode a full Subversion dump stream"""
        if outdir is not None:
            # Make the output directory absolute, to enable sanity checks
            outdir = outdir.resolve()

        self.read_svn_dump_header()
        while self.peek_next_char():
            self.read_revision()
            while self.peek_next_char() == "N":  # For "Node-path: ..."
                self.read_node(outdir=outdir)
            if self.verbose:
                print("")

        # Here, the stream is supposed to be ended
        assert self.reached_eof
        assert self.buffer == b"", repr(self.buffer)


def decode_svn_dump_file(dumpfile: Path, outdir: Optional[Path] = None, verbose: bool = False) -> None:
    """Decode a Subversion dump file"""
    if verbose:
        print(f"Reading {dumpfile}")
    with dumpfile.open("rb") as file_stream:
        stream = SvnDumpStream(file_stream, verbose=verbose)
        stream.decode_svn_dump(outdir=outdir)


def main(argv: Optional[List[str]] = None) -> None:
    """Program entry point"""
    parser = argparse.ArgumentParser(description="Extract a Subversion dump")
    parser.add_argument("dump", nargs="+", type=Path, help="dump file")
    parser.add_argument("-o", "--outdir", type=Path, help="extract files to this output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args(argv)

    for dumpfile in args.dump:
        decode_svn_dump_file(dumpfile, outdir=args.outdir, verbose=args.verbose)


if __name__ == "__main__":
    main()
