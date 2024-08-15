#!/bin/sh
# Build and run the specified docker image

# Ensure we are running inside the directory containing Dockerfiles
cd "$(dirname -- "$0")" || exit $?

DO_BUILD=true
DO_RUN=true
DO_PRETEND=false
USE_VOLUME=false
IMAGE_NAME=''

# Get a base name for an image from a name which comes from the command line
get_base_name() {
    local NAME NAME_NAME
    NAME="$(./get_base_name.sh "$1")"
    if [ -z "$NAME" ]
    then
        echo >&2 "Unable to get base name of $1"
        return 1
    fi

    # Ensure get_base_name.sh is idempotent
    NAME_NAME="$(./get_base_name.sh "$1")"
    if [ "$NAME" != "$NAME_NAME" ]
    then
        echo >&2 "Fatal error: get_base_name.sh is not idempotent: $NAME => $NAME_NAME"
        exit 1
    fi
    echo "$NAME"
}

get_available_bases() {
    local FILENAME BASENAME

    # Filter the available files with get_base_name
    for FILENAME in $(find Dockerfile-* | sort)
    do
        BASENAME="$(get_base_name "$FILENAME")"
        if [ -z "$BASENAME" ]
        then
            echo >&2 "Skipping unknown $FILENAME"
        elif [ "Dockerfile-$BASENAME" != "$FILENAME" ]
        then
            echo >&2 "Error: unexpected base name $BASENAME for $FILENAME"
            exit 1
        else
            echo "$BASENAME"
        fi
    done
}

while getopts "bhn:prv" OPT
do
    case "$OPT" in
        h)
            echo "Usage: $0 [OPTION] NAME"
            echo "Build and run a docker image from the system NAME"
            echo "If NAME is 'all', build for all possible systems"
            echo ""
            echo "Options:"
            echo "  -b       only build an image"
            echo "  -h       display this help and exit"
            echo "  -n IMG   define the tag name of the built image"
            echo "  -p       pretend mode, do not do anything"
            echo "  -r       only run a pre-built image"
            echo "  -v       use a volume when running, to link to git code"
            exit
            ;;
        b)
            DO_BUILD=true
            DO_RUN=false
            ;;
        n)
            IMAGE_NAME="$OPTARG"
            ;;
        p)
            DO_PRETEND=true
            ;;
        r)
            DO_BUILD=false
            DO_RUN=true
            ;;
        v)
            USE_VOLUME=true
            ;;
        \?)
            echo >&2 "Try '$0 -h' for more information."
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))
if [ $# -lt 1 ]
then
    echo >&2 "$0: missing name argument"
    echo >&2 "Use '$0 -h' for more information."
    exit 1
fi

build_and_run() {
    # Build image
    if "$DO_BUILD"
    then
        if "$DO_PRETEND"
        then
            echo "docker buildx build -f 'Dockerfile-$BASE_NAME' -t '$IMAGE_NAME' .."
        else
            docker buildx build -f "Dockerfile-$BASE_NAME" -t "$IMAGE_NAME" .. || return $?
        fi
    fi

    # Run it, with parameters from the command line
    if "$DO_RUN"
    then
        if "$USE_VOLUME"
        then
            if "$DO_PRETEND"
            then
                echo "docker run --rm -t -v '$(pwd)/..:/shared' -i '$IMAGE_NAME' $*"
            else
                # Run docker with a pseudo-TTY and with a volume
                docker run --rm -t -v "$(pwd)/..:/shared" -i "$IMAGE_NAME" "$@" || return $?
            fi
        else
            # Run docker without a volume to base directory
            if "$DO_PRETEND"
            then
                echo "docker run --rm -t -i '$IMAGE_NAME' $*"
            else
                docker run --rm -t -i "$IMAGE_NAME" "$@" || return $?
            fi
        fi
    fi
}

if [ "$1" = 'all' ]
then
    shift
    for BASE_NAME in $(get_available_bases)
    do
        IMAGE_NAME="shared-$BASE_NAME"
        echo "----------------------------------------------------------------"
        echo "            Using image $IMAGE_NAME..."
        echo "----------------------------------------------------------------"
        if ! build_and_run "$@"
        then
            echo >&2 "Failed with base $BASE_NAME"
            exit 1
        fi
    done
elif [ "$1" = 'purge' ]
then
    # Purge the Docker images
    for BASE_NAME in $(get_available_bases)
    do
        IMAGE_NAME="shared-$BASE_NAME"
        if [ -n "$(docker images -q "$IMAGE_NAME")" ]
        then
            docker rmi "shared-$BASE_NAME" || exit $?
        fi
    done
else
    BASE_NAME="$(get_base_name "$1")"
    if [ -z "$BASE_NAME" ]
    then
        echo >&2 "Unknown name '$1'"
        exit 1
    fi
    shift

    if [ -z "$IMAGE_NAME" ]
    then
        IMAGE_NAME="shared-$BASE_NAME"
    fi

    build_and_run "$@" || exit $?
fi
