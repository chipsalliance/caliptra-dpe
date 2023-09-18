# Licensed under the Apache-2.0 license

#!/bin/sh
set -ex

( cd dpe
  cargo build
  cargo build --no-default-features --features=dpe_profile_p384_sha384
  cargo build --release
  cargo test
  cargo test --no-default-features --features=dpe_profile_p384_sha384
  cargo fmt -- --check
  cargo clippy -- --deny=warnings
)
( cd dpe/fuzz
  rustup toolchain install nightly-2023-04-15
  cargo +nightly-2023-04-15 install cargo-fuzz cargo-afl
  cargo fmt --check
  cargo clippy --features libfuzzer-sys
  cargo clippy --features afl
  cargo +nightly-2023-04-15 fuzz build --features libfuzzer-sys
  cargo +nightly-2023-04-15 afl build --features afl
)
( cd simulator
  cargo build
  cargo build --release
  cargo test
  cargo fmt -- --check
  cargo clippy -- --deny=warnings
)
( cd crypto
  cargo build
  cargo build --features=openssl
  cargo build --features=deterministic_rand
  cargo build --no-default-features --features=dpe_profile_p384_sha384
  cargo build --release
  cargo test
  cargo test --no-default-features --features=dpe_profile_p384_sha384
  cargo fmt -- --check
  cargo clippy -- --deny=warnings
)
( cd platform
  cargo build
  cargo build --features=openssl
  cargo build --no-default-features --features=dpe_profile_p384_sha384
  cargo build --release
  cargo test
  cargo test --no-default-features --features=dpe_profile_p384_sha384
  cargo fmt -- --check
  cargo clippy -- --deny=warnings
)
( cd verification
  test -z "$(gofmt -l .)"
  go test
)
(
  cd tools
  cargo build
  cargo fmt -- --check
  cargo clippy -- --deny=warnings
)
ci-tools/file-header-fix.sh --check
