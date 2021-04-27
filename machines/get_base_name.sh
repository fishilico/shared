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

        *debian8*|*jessie*)
            echo "debian8-jessie"
            ;;
        *debian9*|*stretch*)
            echo "debian9-stretch"
            ;;
        *debian10*|*buster*)
            echo "debian10-buster"
            ;;
        *debian11*|*bullseye*)
            echo "debian11-bullseye"
            ;;

        *ubuntu1204*|*ubuntu12.04*|*precise*)
            echo "ubuntu1204-precise"
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

        *fedora22*)
            echo "fedora22"
            ;;
        *fedora23*)
            echo "fedora23"
            ;;
        *fedora24*)
            echo "fedora24"
            ;;
        *fedora25*)
            echo "fedora25"
            ;;
        *fedora26*)
            echo "fedora26"
            ;;
        *fedora27*)
            echo "fedora27"
            ;;
        *fedora28*)
            echo "fedora28"
            ;;
        *fedora29*)
            echo "fedora29"
            ;;
        *fedora30*)
            echo "fedora30"
            ;;
        *fedora31*)
            echo "fedora31"
            ;;
        *fedora32*)
            echo "fedora32"
            ;;
        *fedora33*)
            echo "fedora33"
            ;;
        *fedora34*)
            echo "fedora34"
            ;;

        *gentoo*)
            echo "gentoo-amd64-hardened"
            ;;

        *)
            echo >&2 "Error: invalid name $NAME (from $1)"
            exit 1
            ;;
    esac
    shift
done
