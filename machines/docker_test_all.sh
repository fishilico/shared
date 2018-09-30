#!/bin/sh
# Build and run all Docker images in order to perform tests
# If running on a system with low storage, the images are automatically removed

# Ensure we are running inside the directory containing Dockerfiles
cd "$(dirname -- "$0")" || exit $?

purge_docker_cache() {
    local UNTAGGED_NUM NONE_VER_NUM

    # Remove untagged images
    UNTAGGED_NUM="$(docker images | awk '{ if($1 == "<none>")print $3 }' | wc -l)"
    echo "There are currently $UNTAGGED_NUM untagged images."
    if [ "$UNTAGGED_NUM" -gt 0 ]
    then
        docker images | awk '{ if($1 == "<none>")print $3 }' | xargs docker rmi
        UNTAGGED_NUM="$(docker images | awk '{ if($1 == "<none>")print $3 }' | wc -l)"
        echo "After cleanup, there remains $UNTAGGED_NUM untagged images."
    fi

    # Remove untagged versions (which appear after an update)
    NONE_VER_NUM="$(docker images | awk '{ if($2 == "<none>")print $3 }' | wc -l)"
    echo "There are currently $NONE_VER_NUM images with untagged versions."
    if [ "$NONE_VER_NUM" -gt 0 ]
    then
        docker images | awk '{ if($2 == "<none>")print $3 }' | xargs docker rmi
        NONE_VER_NUM="$(docker images | awk '{ if($2 == "<none>")print $3 }' | wc -l)"
        echo "After cleanup, there remains $NONE_VER_NUM images with untagged versions."
    fi
}

test_dockerfile() {
    local DOCKERFILE BASE_NAME BASE_NAME_NAME IMAGE_NAME DISK_SIZE

    DOCKERFILE="$1"
    BASE_NAME="$(./get_base_name.sh "$1")"
    if [ -z "$BASE_NAME" ]
    then
        echo >&2 "Unable to get base name of $1"
        return 1
    fi

    # Ensure get_base_name.sh is idempotent
    BASE_NAME_NAME="$(./get_base_name.sh "$1")"
    if [ "$BASE_NAME" != "$BASE_NAME_NAME" ]
    then
        echo >&2 "Fatal error: get_base_name.sh is not idempotent: $BASE_NAME => $BASE_NAME_NAME"
        exit 1
    fi

    IMAGE_NAME="shared-$BASE_NAME"

    # Grab the previous Docker image ID, if any
    PREVIOUS_IMAGE_ID="$(docker images --format '{{.ID}}' "$IMAGE_NAME" 2>/dev/null)"

    echo "----------------------------------------------------------------"
    echo "            Using image $IMAGE_NAME..."
    echo "----------------------------------------------------------------"
    if ! ./docker_build_run.sh "$BASE_NAME"
    then
        echo >&2 "Failed with base $BASE_NAME"
        exit 1
    fi

    # Remove the previous image if it is different
    if [ -n "$PREVIOUS_IMAGE_ID" ]
    then
        NEW_IMAGE_ID="$(docker images --format '{{.ID}}' "$IMAGE_NAME" 2>/dev/null)"
        if [ "$NEW_IMAGE_ID" != "$PREVIOUS_IMAGE_ID" ]
        then
            PREV_IMAGE_LINE="$(docker images --format '{{.ID}} {{.Repository}}:{{.Tag}}' |grep "$PREVIOUS_IMAGE_ID")"
            if [ "$PREV_IMAGE_LINE" != "$PREVIOUS_IMAGE_ID <none>:<none>" ]
            then
                echo >&2 "Unexpected docker image line for previous image of $IMAGE_NAME ($PREVIOUS_IMAGE_ID):"
                echo >&2 "    $PREV_IMAGE_LINE"
                return 1
            fi
            echo "Removing previous image of $IMAGE_NAME ($PREVIOUS_IMAGE_ID)"
            docker rmi "$PREVIOUS_IMAGE_ID"
        fi
    fi

    # Purge the image if there is little room available
    DISK_SIZE="$(LANG=C df --output=size --block-size=G /var/lib/docker | sed -n '$s/G$//p' | tr -d ' ')"
    if [ "$DISK_SIZE" -lt 50 ]
    then
        echo "Removing image $IMAGE_NAME as the disk size is $DISK_SIZE GB"
        docker rmi "$IMAGE_NAME" || exit $?
        purge_docker_cache
    else
        echo "Keeping image $IMAGE_NAME as the disk size is $DISK_SIZE GB"
    fi
}

# If the input is not a TTY, create one with script
# Otherwise "docker run -t" complains with "The input device is not a TTY"
if ! [ -t 0 ]
then
    echo "Re-executing using script in order to get a TTY"
    exec script -qe -c "./docker_test_all.sh $*" /dev/null
fi

# Allow specifying Dockerfiles directly on the command line
if [ "$#" -gt 0 ]
then
    while [ "$#" -gt 0 ]
    do
        test_dockerfile "$1" || exit $?
        shift
    done
else
    for DOCKERFILE in $(find Dockerfile-* | sort)
    do
        test_dockerfile "$DOCKERFILE" || exit $?
    done
fi
