#!/bin/sh
set -eu
# Docker Desktop may project Windows bind mounts as 0777. Copy only this
# container's leaf key into a private tmpfs; never relax the runtime key check.
umask 077
cp /run/input/leaf.key /run/shadow/private/leaf.key
chmod 600 /run/shadow/private/leaf.key
exec "$@"
