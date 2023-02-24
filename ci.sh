#!/bin/sh
set -ex

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
  # cargo fmt -- --check
  # cargo clippy -- --deny=warnings
)
