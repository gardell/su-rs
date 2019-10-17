#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail -o xtrace

TARGET=${TARGET:-debug}

if [ ${TARGET} == "release" ]; then
    cargo build --release
else
    cargo build
fi

sudo chown root:root target/${TARGET}/su-rs
sudo chmod u+s target/${TARGET}/su-rs
