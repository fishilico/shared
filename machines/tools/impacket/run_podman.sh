#!/usr/bin/env bash
# Run impacket in a Podman environment
# Example:
# - Spawn a SMB share with authentication (remove -username and -password to support any authentication):
#
#   sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0
#   ./run_podman.sh -p 445:445 -v "$(pwd):/tmp/serve" smbserver.py -smb2support -username user -password secret share /tmp/serve

cd "$(dirname -- "$0")" || exit $?

# Use "-" to skip building
if [ $# -ge 1 ] && [[ "$1" == '-' ]]
then
    shift
else
    # Clone impacket repository, if needed
    [ -d impacket ] || ./clone_impacket.sh || exit $?
    # Build the Podman image
    podman build . -t impacket || exit $?
fi

# Forward arguments to Podman before the name of the image
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

exec podman run -it --rm "${RUN_ARGS[@]}" impacket "$@"
