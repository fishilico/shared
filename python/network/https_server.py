#!/usr/bin/env python3
"""Run a HTTPS server

Test with:
    ./https_server.py -k /tmp/test_https_server.key -c /tmp/test_https_server.crt -g localhost test example.com
    curl --cacert /tmp/test_https_server.crt --resolve test:443:127.0.0.1 https://test

"""
from __future__ import annotations

import argparse
import http.server
import socketserver
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


# Use SimpleHTTPRequestHandler to list directories
class MyHttpsHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:
        name = self.request.context.my_server_name
        print(f"[HTTPS {name!r}] HEAD {self.path}")
        for key, value in self.headers.items():
            print(f"  {key}: {value}")
        if self.path == "/":
            encoded = b"OK GET (and HEAD)\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        name = self.request.context.my_server_name
        print(f"[HTTPS {name!r}] GET {self.path}")
        for key, value in self.headers.items():
            print(f"  {key}: {value}")
        if self.path == "/":
            encoded = b"OK GET (and HEAD)\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        name = self.request.context.my_server_name
        print(f"[HTTPS {name!r}] POST {self.path}")
        for key, value in self.headers.items():
            print(f"  {key}: {value}")
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        print(f"  POST data: {post_data!r}")

        if self.path == "/":
            encoded = b"OK POST\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def generate_https_certificate(key_path: Path, cert_path: Path, names: Sequence[str]) -> None:
    """Generate a HTTPS key and certificate, with a new certificate authority

    Equivalent shell commands:

        cat > server.cnf << EOF
        [req]
        default_bits = 2048
        default_md = sha256
        prompt = no
        encrypt_key = no
        distinguished_name = dn
        req_extensions = v3_req

        [dn]
        CN = localhost

        [v3_req]
        basicConstraints = CA:FALSE
        subjectKeyIdentifier = hash
        keyUsage = keyEncipherment, dataEncipherment
        extendedKeyUsage = serverAuth
        subjectAltName = @alt_names

        [alt_names]
        DNS.1 = localhost
        DNS.2 = example.fr
        EOF

        # Create Certificate Authority (CA)
        openssl req -newkey rsa:2048 -nodes -x509 -days 365 -subj "/CN=My Root CA" -keyout ca.key -out ca.crt
        # Create Certificate Signature Request (CSR) and private key
        openssl req -new -config server.cnf -keyout server.key -out server.csr
        # Sign the certificate
        openssl x509 -req -days 365 -copy_extensions=copy
            -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
    """
    with tempfile.TemporaryDirectory(prefix="gen-https-cert") as tmpdir:
        tmpdir_path = Path(tmpdir)
        tmp_ca_key_path = tmpdir_path / "ca.key"
        tmp_ca_crt_path = tmpdir_path / "ca.crt"
        server_cnf_path = tmpdir_path / "server.cnf"
        server_csr_path = tmpdir_path / "server.csr"
        print("Generating CA key")
        subprocess.run(
            (
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-x509",
                "-days",
                "365",
                "-subj",
                "/CN=My Root CA",
                "-keyout",
                str(tmp_ca_key_path),
                "-out",
                str(tmp_ca_crt_path),
            ),
            stdin=subprocess.DEVNULL,
            check=True,
        )
        server_config = f"""
[req]
default_bits = 2048
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = {names[0]}

[v3_req]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]"""
        for idx, name in enumerate(names, start=1):
            server_config += f"\nDNS.{idx} = {name}"
        with server_cnf_path.open("w") as fcnf:
            print(server_config, file=fcnf)
        print("Generating server key and CSR")
        subprocess.run(
            (
                "openssl",
                "req",
                "-new",
                "-config",
                str(server_cnf_path),
                "-keyout",
                str(key_path),
                "-out",
                str(server_csr_path),
            ),
            stdin=subprocess.DEVNULL,
            check=True,
        )
        print("Signing the certificate")
        subprocess.run(
            (
                "openssl",
                "x509",
                "-req",
                "-days",
                "365",
                "-copy_extensions=copy",
                "-in",
                str(server_csr_path),
                "-CA",
                str(tmp_ca_crt_path),
                "-CAkey",
                str(tmp_ca_key_path),
                "-out",
                cert_path,
            ),
            stdin=subprocess.DEVNULL,
            check=True,
        )
        # Add the CA certificate to the signed certificate
        with tmp_ca_crt_path.open("r") as fca:
            ca_cert = fca.read()
        with cert_path.open("a") as fcrt:
            fcrt.write(ca_cert)


class ReuseAddrTCPServer(socketserver.TCPServer):
    """TCP server allowing to resuse the address"""

    # https://docs.python.org/3.12/library/socketserver.html#socketserver.BaseServer.allow_reuse_address
    allow_reuse_address = True


def my_https_sni_cb(sslobj: ssl.SSLSocket, servername: str | None, sslctx: ssl.SSLContext) -> None:
    """Callback for HTTP Server Name Indication"""
    # print(f"[HTTPS handshake] server name {servername!r}")
    # Save the server name in the current context
    sslctx.my_server_name = servername


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a HTTPS server")
    parser.add_argument("-a", "--addr", type=str, default="0.0.0.0", help="IP address to use for binding")
    parser.add_argument("-p", "--port", type=int, default=443, help="TCP port (default: 443)")
    parser.add_argument("-k", "--key", type=Path, help="server private key")
    parser.add_argument("-c", "--cert", type=Path, help="server certificate")
    parser.add_argument(
        "-g", "--generate", nargs="+", type=str, help="generate a private key and a certificate for the given name(s)"
    )
    args = parser.parse_args()

    if not args.key:
        parser.error("missing --key ")
    if not args.cert:
        parser.error("missing --cert")

    if args.generate:
        generate_https_certificate(args.key, args.cert, args.generate)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.sni_callback = my_https_sni_cb

    with ReuseAddrTCPServer((args.addr, args.port), MyHttpsHandler) as httpd:
        httpd.socket = context.wrap_socket(sock=httpd.socket, server_side=True)
        print(f"Starting HTTPS server on {args.addr}:{args.port}")
        sys.stdout.flush()
        httpd.serve_forever()
