#!/bin/sh
set -ex

# TODO: Remove once we don't generate those warnings. They currently polute the
# script output and prevents easily identifying more important warnings and
# errors.
export RUSTFLAGS='-A dead_code -A unused_variables'

( cd dpe
  cargo build
  # cargo build --no-default-features --features=dpe_profile_p384_sha384
  cargo build --release
  cargo test
  # cargo test --no-default-features --features=dpe_profile_p384_sha384
  cargo fmt -- --check
  # cargo clippy -- --deny=warnings
)
( cd simulator
  cargo build
  cargo build --release
  cargo test
  cargo fmt -- --check
  cargo clippy -- --deny=warnings
)
