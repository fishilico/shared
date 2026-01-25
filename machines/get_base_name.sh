#!/bin/sh
# Get a base name for an image from a name which comes from the command line
while [ "$#" -ge 1 ]
do
    NAME="$1"

    # Drop "Dockerfile-" prefix, which allows using file name completion
    NAME="${NAME#*Dockerfile-}"

    # Drop special symbols and make lowercase
    NAME="$(echo "$NAME" | tr -cd 'a-zA-Z0-9.' | tr '[:upper:]' '[:lower:]')"

    # Recognize keywords
    case "$NAME" in
        *arch*)
            echo "archlinux"
            ;;

        *alpine33*|*alpine3.3*)
            echo "alpine3.3"
            ;;
        *alpine34*|*alpine3.4*)
            echo "alpine3.4"
            ;;
        *alpine35*|*alpine3.5*)
            echo "alpine3.5"
            ;;
        *alpine36*|*alpine3.6*)
            echo "alpine3.6"
            ;;
        *alpine37*|*alpine3.7*)
            echo "alpine3.7"
            ;;
        *alpine38*|*alpine3.8*)
            echo "alpine3.8"
            ;;
        *alpine39*|*alpine3.9*)
            echo "alpine3.9"
            ;;
        *alpine310*|*alpine3.10*)
            echo "alpine3.10"
            ;;
        *alpine311*|*alpine3.11*)
            echo "alpine3.11"
            ;;
        *alpine312*|*alpine3.12*)
            echo "alpine3.12"
            ;;
        *alpine313*|*alpine3.13*)
            echo "alpine3.13"
            ;;
        *alpine314*|*alpine3.14*)
            echo "alpine3.14"
            ;;
        *alpine315*|*alpine3.15*)
            echo "alpine3.15"
            ;;
        *alpine316*|*alpine3.16*)
            echo "alpine3.16"
            ;;
        *alpine317*|*alpine3.17*)
            echo "alpine3.17"
            ;;
        *alpine318*|*alpine3.18*)
            echo "alpine3.18"
            ;;
        *alpine319*|*alpine3.19*)
            echo "alpine3.19"
            ;;
        *alpine320*|*alpine3.20*)
            echo "alpine3.20"
            ;;
        *alpine321*|*alpine3.21*)
            echo "alpine3.21"
            ;;
        *alpine322*|*alpine3.22*)
            echo "alpine3.22"
            ;;
        *alpine323*|*alpine3.23*)
            echo "alpine3.23"
            ;;

        *debian10*|*buster*)
            echo "debian10-buster"
            ;;
        *debian11*|*bullseye*)
            echo "debian11-bullseye"
            ;;
        *debian12*|*bookworm*)
            echo "debian12-bookworm"
            ;;
        *debian13*|*trixie*)
            echo "debian13-trixie"
            ;;
        *debian14*|*forky*)
            echo "debian14-forky"
            ;;

        *ubuntu1404*|*ubuntu14.04*|*trusty*)
            echo "ubuntu1404-trusty"
            ;;
        *ubuntu1604*|*ubuntu16.04*|*xenial*)
            echo "ubuntu1604-xenial"
            ;;
        *ubuntu1804*|*ubuntu18.04*|*bionic*)
            echo "ubuntu1804-bionic"
            ;;
        *ubuntu2004*|*ubuntu20.04*|*focal*)
            echo "ubuntu2004-focal"
            ;;
        *ubuntu2204*|*ubuntu22.04*|*jammy*)
            echo "ubuntu2204-jammy"
            ;;
        *ubuntu2404*|*ubuntu24.04*|*noble*)
            echo "ubuntu2404-noble"
            ;;
        *ubuntu2604*|*ubuntu26.04*|*resolute*)
            echo "ubuntu2604-resolute"
            ;;

        *fedora22*)
            echo "fedora22"
            ;;
        *fedora25*)
            echo "fedora25"
            ;;
        *fedora30*)
            echo "fedora30"
            ;;
        *fedora35*)
            echo "fedora35"
            ;;
        *fedora40*)
            echo "fedora40"
            ;;
        *fedora41*)
            echo "fedora41"
            ;;
        *fedora42*)
            echo "fedora42"
            ;;
        *fedora43*)
            echo "fedora43"
            ;;
        *fedora44*)
            echo "fedora44"
            ;;

        *)
            echo >&2 "Error: invalid name $NAME (from $1)"
            exit 1
            ;;
    esac
    shift
done
