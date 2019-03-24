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
"""Helper functions for cryptography functions"""
import logging


try:
    import cryptography.x509
except ImportError:
    HAVE_CRYPTOGRAPHY = False
else:
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    HAVE_CRYPTOGRAPHY = True


logger = logging.getLogger(__name__)


def report_if_missing_cryptography():
    """Log a message if cryptography module is missing"""
    if not HAVE_CRYPTOGRAPHY:
        logger.warning("Python cryptography is not installed")


def describe_der_certificate(certificate):
    """Craft a description of a certificate in DER format"""
    if not HAVE_CRYPTOGRAPHY:
        return None

    backend = cryptography.hazmat.backends.default_backend()
    cert = cryptography.x509.load_der_x509_certificate(certificate, backend)
    try:
        cert_subject = cert.subject
    except ValueError as exc:
        # This happens for example when using C=Unknown
        # ("Country name must be a 2 character country code")
        logger.error("PyCryptography failed to load the certificate subject: %s", exc)
        cert_subject = None

    try:
        cert_issuer = cert.issuer
    except ValueError as exc:
        logger.error("PyCryptography failed to load the certificate issuer: %s", exc)
        cert_issuer = None

    desc = "{} ({}...{})".format(
        cert_subject if cert_subject is not None else "(invalid subject)",
        cert.not_valid_before.strftime('%Y-%m-%d'),
        cert.not_valid_after.strftime('%Y-%m-%d'),
    )
    if cert_issuer is not None:
        if cert_issuer == cert_subject:
            desc += " self-signed"
        else:
            desc += " issued by {}".format(cert_issuer)
    return desc
