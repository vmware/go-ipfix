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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

MODE="dev"

_usage="Usage: $0 [--mode (dev|release)] [--help|-h]
Generate a YAML manifest for ipfix collector, using Helm, and print it to stdout.
        --mode (dev|release)  Choose the configuration variant that you need (default is 'dev')
        --help, -h            Print this message and exit

In 'dev' mode, argument [--port <port> --proto (tcp|udp)] can be provided.
If no argument is given, collector will be configured with the default argument values.
        --port <port>         Specify the port that will be listened on by the collector. Default is 4739.
        --proto (tcp|udp)       Speicify the protocol. Default is tcp.
Example: ./generate-manifest-collector.sh --mode dev --port 4739 --proto tcp > ../build/yamls/ipfix-collector.yaml

In 'release' mode, environment variable IMG_TAG must be set.

This tool uses helm (https://github.com/helm/helm) to generate templated manifests for
running ipfix collector. You can set the HELM environment variable to the path of the
helm binary you want us to use. Otherwise we will look for helm in your PATH and your
GOPATH. If we cannot find helm there, we will try to install it."

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    --port)
    PORT="$2"
    shift 2
    ;;
    --proto)
    PROTO="$2"
    shift 2
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)    # unknown option
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

if [ "$MODE" != "dev" ] && [ "$MODE" != "release" ]; then
    echoerr "--mode must be one of 'dev' or 'release'"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_TAG" ]; then
    echoerr "In 'release' mode, environment variable IMG_TAG must be set"
    print_help
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/verify-helm.sh

if [ -z "$HELM" ]; then
    HELM="$(verify_helm)"
elif ! $HELM version > /dev/null 2>&1; then
    echoerr "$HELM does not appear to be a valid helm binary"
    print_help
    exit 1
fi

cd $THIS_DIR/../build/yamls/collector

if [ "$MODE" == "dev" ]; then
    sed -i.bak -e "s/^image_tag.*/image_tag: latest/g" values.yaml
    if [[ $PORT != "" ]]; then
        sed -i.bak -e "s/^port.*/port: $PORT/g" values.yaml
    fi
    if [[ $PROTO != "" ]]; then
        sed -i.bak -e "s/^protocol.*/protocol: $PROTO/g" values.yaml
    fi
    $HELM template "." -f "./templates/ipfix-collector.yaml"
    rm values.yaml.bak
fi

if [ "$MODE" == "release" ]; then
    # update the Chart version by the newest release version
    sed -i.bak -e "s/^version.*/version: ${IMG_TAG:1}/g" Chart.yaml
    rm "Chart.yaml.bak"
    # replace the line starting with "image_tag", and create a backup of the original one
    sed -i.bak -e "s/^image_tag.*/image_tag: $IMG_TAG/g" values.yaml

    $HELM template "." -f "./templates/ipfix-collector.yaml"
    cp -f "values.yaml.bak" "values.yaml"
    rm "values.yaml.bak"
fi
