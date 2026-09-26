#!/usr/bin/env bash
# Build Hao's ZKMath + our extension inside a rootless podman container.
#   ./build.sh            build everything (binaries end up in build/emp-zk/bin)
#   ./build.sh --rebuild  rebuild the container image first
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
IMG=zkmath-ext:latest
if [ "${1:-}" = "--rebuild" ] || ! podman image exists "$IMG"; then
    podman build -t "$IMG" -f "$HERE/Containerfile" "$HERE"
    [ "${1:-}" = "--rebuild" ] && shift
fi
mkdir -p "$HERE/build"
podman run --rm -v "$HERE:/ext:z" -v "$HERE/build:/build:z" "$IMG" bash /ext/scripts/container_build.sh "$@"
