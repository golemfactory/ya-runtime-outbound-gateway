#!/bin/bash

set -e

DEFAULT_INSTALL_DIR=~/.local/lib/yagna/plugins

cargo build --release -p ya-runtime-outbound-gateway

mkdir -p ${DEFAULT_INSTALL_DIR}/ya-runtime-outbound-gateway

echo "Installing in ${DEFAULT_INSTALL_DIR}"

cp target/release/ya-runtime-outbound-gateway ${DEFAULT_INSTALL_DIR}/ya-runtime-outbound-gateway/ya-runtime-outbound-gateway
cp conf/ya-runtime-outbound-gateway.json ${DEFAULT_INSTALL_DIR}/ya-runtime-outbound-gateway.json
