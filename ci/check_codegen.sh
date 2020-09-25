#!/usr/bin/env bash


# This script makes sure that the checked-in mock files ("fake" packages) are
# up-to-date.

set -ex

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $THIS_DIR/.. > /dev/null

make codegen

diff=$(git status --porcelain pkg)

if [ ! -z "$diff" ]; then
    echo "The generated mock files are not up-to-date" >&2
    echo "You can regenerate them with 'make codegen' and commit the changes" >&2
    exit 1
fi
