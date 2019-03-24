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
"""Some functions helpful to handle binary data"""
import binascii
import logging
import subprocess
import sys
import threading


logger = logging.getLogger(__name__)


def xx(data):
    """One-line hexadecimal representation of binary data"""
    return binascii.hexlify(data).decode('ascii')


def indentify_byte_stream(indent_bytes, stream):
    """Flush the content of a stream of bytes with some indentation"""
    need_indent_before_data = True
    stdout_buffer = sys.stdout.buffer if sys.version_info >= (3,) else sys.stdout
    while True:
        data = stream.read(4096)
        if not data:
            break
        if need_indent_before_data:
            stdout_buffer.write(indent_bytes)
        if data.endswith(b'\n'):
            need_indent_before_data = True
            stdout_buffer.write(data[:-1].replace(b'\n', b'\n' + indent_bytes))
            stdout_buffer.write(b'\n')
        else:
            need_indent_before_data = False
            stdout_buffer.write(data.replace(b'\n', b'\n' + indent_bytes))
    stdout_buffer.flush()


def run_process_with_input(cmdline, data, fatal=False, indent=None):
    """Run the given command with the given data and show its output in colors"""
    if indent is None:
        logger.info("Running %s", ' '.join(cmdline))
    sys.stdout.flush()  # Flush stdout because the subprocess may write too
    if indent:
        # Start a thread to indent the output
        proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        indent_thread = threading.Thread(
            target=indentify_byte_stream,
            args=(indent.encode('ascii'), proc.stdout))
        indent_thread.start()
    else:
        proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE)

    # Send input data to the process
    if data:
        proc.stdin.write(data)
    proc.stdin.close()
    ret = proc.wait()
    if indent:
        indent_thread.join()
    if ret != 0:
        logger.error("Command %s returned %d", ' '.join(cmdline), ret)
        if fatal:
            raise ValueError("Command {} failed".format(cmdline[0]))
        return False
    return True


def run_openssl_asn1parse(der_data, fatal=True, indent=None):
    """Show the ASN.1 structure of data encoded in DER format, using openssl"""
    run_process_with_input(
        ['openssl', 'asn1parse', '-i', '-dump', '-inform', 'DER'],
        der_data, fatal=fatal, indent=indent)


def run_openssl_show_text_pem(openssl_cmd, der_data, list_only=False, show_pem=False, indent=None):
    """Show a DER-encoded object using openssl"""
    if list_only:
        # do not show anything when listing items
        return
    cmdline = ['openssl', openssl_cmd, '-inform', 'DER']
    run_process_with_input(cmdline + ['-text', '-noout'], der_data, fatal=False, indent=indent)
    # Never show the PEM-encoded certificate with indentation
    if show_pem:
        run_process_with_input(cmdline + ['-outform', 'PEM'], der_data, fatal=False, indent='')


def run_openssl_show_cert(cert, list_only=False, show_pem=False, indent=None):
    """Show a DER-encoded certificate using openssl"""
    run_openssl_show_text_pem('x509', cert, list_only=list_only, show_pem=show_pem, indent=indent)


def run_openssl_show_dsa(key, list_only=False, show_pem=False, indent=None):
    """Show a DER-encoded DSA private key using openssl"""
    run_openssl_show_text_pem('dsa', key, list_only=list_only, show_pem=show_pem, indent=indent)


def run_openssl_show_rsa(key, list_only=False, show_pem=False, indent=None):
    """Show a DER-encoded RSA private key using openssl"""
    run_openssl_show_text_pem('rsa', key, list_only=list_only, show_pem=show_pem, indent=indent)
