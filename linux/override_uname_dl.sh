#!/bin/sh
# Override uname() call with dynamic load

while [ $# -ge 1 ]
do
    case "$1" in
        -s|--kernel-name)
            FAKEUNAME_S="$2"
            export FAKEUNAME_S
            shift 2;;
        -n|--nodename)
            FAKEUNAME_N="$2"
            export FAKEUNAME_N
            shift 2;;
        -r|--kernel-release)
            FAKEUNAME_R="$2"
            export FAKEUNAME_R
            shift 2;;
        -v|--kernel-version)
            FAKEUNAME_V="$2"
            export FAKEUNAME_V
            shift 2;;
        -m|--machine)
            FAKEUNAME_M="$2"
            export FAKEUNAME_M
            shift 2;;
        -h|--help)
            echo "Usage: $0 [options] [--] [command]"
            echo "Options:"
            echo "    -s kernel-name"
            echo "    -n nodename"
            echo "    -r kernel-release"
            echo "    -v kernel-version"
            echo "    -m machine"
            echo "If no command is supplied, 'uname' -a is used"
            exit 0;;
        --)
            shift
            break;;
        *)
            break;;
    esac
done

[ $# -ge 1 ] || set uname -a
LD_PRELOAD="${0%.sh}.so" exec "$@"
