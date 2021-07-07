#!/bin/bash
set -ex

RUST_TOOLCHAIN=$(cat rust-toolchain)
# We specify a particular rustup version and a SHA256 hash for
# `rustup-init.sh`, computed ourselves and hardcoded here.
RUSTUP_LATEST_VERSION=1.24.3
OUR_RUSTUP_INIT_SHA="a3cb081f88a6789d104518b30d4aa410009cd08c3822a1226991d6cf0442a0f8"

curl --proto '=https' --tlsv1.2 -sSf -O \
  https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_LATEST_VERSION}/rustup-init.sh
# Verify checksum of rustup script.
echo "${OUR_RUSTUP_INIT_SHA} rustup-init.sh" | sha256sum --check -
# Run rustup.
sh rustup-init.sh --default-toolchain ${RUST_TOOLCHAIN} -y
export PATH="${HOME}/.cargo/bin:${PATH}"


cd /io

for PYBIN in /opt/python/cp{35,36,37,38,39}*/bin; do
    "${PYBIN}/pip" install -U setuptools wheel setuptools-rust
    "${PYBIN}/python" setup.py bdist_wheel
done

for whl in dist/*.whl; do
    auditwheel repair "$whl" -w dist/
done
