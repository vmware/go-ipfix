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

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ostype=""
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    ostype="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    ostype="darwin"
else
    >&2 echo "Unsupported OS type $OSTYPE"
    return 1
fi

_BINDIR="$THIS_DIR/.bin"
# Must be an exact match, as the generated YAMLs may not be consistent across
# versions
_HELM_VERSION="v3.2.4"

# Ensure the helm tool exists and is the correct version, or installs it
verify_helm() {
    # Check if there is already a helm binary in $_BINDIR and if yes, check
    # if the version matches the expected one.
    local helm="$(PATH=$_BINDIR/${ostype}-amd64 command -v helm)"
    if [ -x "$helm" ]; then
        # Verify version if helm was already installed.
        local helm_version="$($helm version --short)"
        # should work with:
        # - v3.5.4+g1b5edb6
        helm_version="${helm_version%+*}"
        if [ "${helm_version}" == "${_HELM_VERSION}" ]; then
            # If version is exact match, stop here.
            echo "$helm"
            return 0
        fi
        >&2 echo "Detected helm version ($helm_version) does not match expected one ($_HELM_VERSION), installing correct version"
    fi

    >&2 echo "Installing helm"

    local helm_url="https://get.helm.sh/helm-${_HELM_VERSION}-${ostype}-amd64.tar.gz"
    curl -sLo helm.tar.gz "${helm_url}" || return 1
    mkdir -p "$_BINDIR" || return 1
    tar -xzf helm.tar.gz -C "$_BINDIR" || return 1
    rm -f helm.tar.gz
    helm="$_BINDIR/${ostype}-amd64/helm"
    echo "$helm"
    return 0
}
