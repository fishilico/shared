#!/usr/bin/env bash
# Run impacket in a Docker environment
# Example:
# - Spawn a SMB share with authentication (remove -username and -password to support any authentication):
#
#   ./run_docker.sh -p 445:445 -v "$(pwd):/tmp/serve" smbserver.py -smb2support -username user -password secret share /tmp/serve

cd "$(dirname -- "$0")" || exit $?

# Use "-" to skip building
if [ $# -ge 1 ] && [[ "$1" == '-' ]]
then
    shift
else
    # Clone impacket repository, if needed
    [ -d impacket ] || ./clone_impacket.sh || exit $?
    # Build the Docker image
    docker build . -t impacket || exit $?
fi

# Forward arguments to Docker before the name of the image
RUN_ARGS=()
while [ $# -ge 1 ]
do
    case "$1" in
        -[pv]|--port|--volumne)
            RUN_ARGS+=( "$1" "$2" )
            shift 2
            ;;
        -*)
            RUN_ARGS+=( "$1" )
            shift
            ;;
        *)
            break
            ;;
    esac
done

exec docker run -it --rm "${RUN_ARGS[@]}" impacket "$@"
