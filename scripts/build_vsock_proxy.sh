#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

VIPROXY_VERSION="v0.1.2"

target_architecture=${CDK_TARGET_ARCHITECTURE:-linux/amd64}
THIRD_PARTY_TARGET_DIRECTORY="./application/attestation/third_party"

if [[ ! -d ${THIRD_PARTY_TARGET_DIRECTORY} ]]; then
  mkdir -p ${THIRD_PARTY_TARGET_DIRECTORY}
fi

cd "${THIRD_PARTY_TARGET_DIRECTORY}"

if [[ -d "./viproxy" ]]; then
  rm -rf "./viproxy"
fi

git clone --depth 1 --branch "${VIPROXY_VERSION}" https://github.com/brave/viproxy.git
cd ./viproxy

architecture=$(echo "${target_architecture}" | cut -d "/" -f 2)
env CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" go build -o proxy ./example/main.go
cd ..
