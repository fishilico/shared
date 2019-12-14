#!/bin/sh
cd "$(dirname -- "$0")" || exit $?
exec git clone https://github.com/SecureAuthCorp/impacket
