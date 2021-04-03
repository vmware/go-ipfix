#!/usr/bin/env bash

# Copyright 2021 Go-ipfix Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script generates all the assets required for an Go-ipfix Github release to
# the provided directory.
# Usage: VERSION=v1.0.0 ./prepare-assets.sh <output dir>

set -eo pipefail

function echoerr {
    >&2 echo "$@"
    exit 1
}

if [ -z "$VERSION" ]; then
    echoerr "Environment variable VERSION must be set"
fi

if [ -z "$1" ]; then
    echoerr "Argument required: output directory for assets"
fi

mkdir -p "$1"
OUTPUT_DIR=$(cd "$1" && pwd)

export IMG_TAG=$VERSION

./hack/generate-manifest-collector.sh --mode release > "$OUTPUT_DIR"/ipfix-collector.yaml

ls "$OUTPUT_DIR" | cat
