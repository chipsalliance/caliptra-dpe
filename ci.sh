# Licensed under the Apache-2.0 license

#!/bin/sh
set -ex

# TODO: Support building the simulator for different profiles
function build_rust_targets() {
  profile=$1

  cargo build --release --manifest-path dpe/Cargo.toml --features=$profile,no-cfi --no-default-features

  cargo build --release --manifest-path crypto/Cargo.toml --no-default-features
  cargo build --release --manifest-path platform/Cargo.toml --no-default-features
  cargo build --release --manifest-path dpe/Cargo.toml --features=$profile --no-default-features
  cargo build --release --manifest-path simulator/Cargo.toml --features=$profile,rustcrypto --no-default-features
  cargo build --release --manifest-path tools/Cargo.toml --features=$profile --no-default-features

  cargo build --manifest-path crypto/Cargo.toml --no-default-features
  cargo build --manifest-path platform/Cargo.toml --no-default-features
  cargo build --manifest-path dpe/Cargo.toml --features=$profile --no-default-features
  cargo build --manifest-path simulator/Cargo.toml --features=$profile,rustcrypto --no-default-features
  cargo build --manifest-path tools/Cargo.toml --features=$profile --no-default-features
}

function lint_rust_targets() {
  profile=$1

  cargo clippy --manifest-path crypto/Cargo.toml --no-default-features -- --deny=warnings
  cargo clippy --manifest-path platform/Cargo.toml --no-default-features -- --deny=warnings
  cargo clippy --manifest-path dpe/Cargo.toml --features=$profile --no-default-features -- --deny=warnings
  cargo clippy --manifest-path simulator/Cargo.toml --features=$profile,rustcrypto --no-default-features -- --deny=warnings
  cargo clippy --manifest-path tools/Cargo.toml --features=$profile --no-default-features -- --deny=warnings
}

function format_rust_targets() {
  cargo fmt --manifest-path crypto/Cargo.toml --check
  cargo fmt --manifest-path platform/Cargo.toml --check
  cargo fmt --manifest-path dpe/Cargo.toml --check
  cargo fmt --manifest-path simulator/Cargo.toml --check
  cargo fmt --manifest-path tools/Cargo.toml --check
}

function format_go_targets() {
  ( cd verification
    test -z "$(gofmt -l .)"
    test -z "$(golint)"
  )
}

# TODO: Support building the simulator for different profiles
function test_rust_targets() {
  profile=$1

  cargo test --manifest-path platform/Cargo.toml --no-default-features
  cargo test --manifest-path crypto/Cargo.toml --no-default-features
  cargo test --manifest-path dpe/Cargo.toml --features=$profile --no-default-features -- --test-threads=1
  cargo test --manifest-path simulator/Cargo.toml --features=$profile,rustcrypto --no-default-features
}

# TODO: Support building the simulator for different profiles
function run_verification_tests() {
  profile=$1
  crypto=$2

  cargo build --manifest-path simulator/Cargo.toml --features=$profile,$crypto --no-default-features

  ( cd verification/testing
    go test -v
  )
}

format_rust_targets
format_go_targets

# Build check for ML-DSA
# TODO: Verification tests
build_rust_targets ml-dsa
test_rust_targets ml-dsa
lint_rust_targets ml-dsa

# Run tests for P256 profile
build_rust_targets dpe_profile_p256_sha256
lint_rust_targets dpe_profile_p256_sha256
test_rust_targets dpe_profile_p256_sha256
run_verification_tests dpe_profile_p256_sha256 rustcrypto

# Run tests for P384 profile
build_rust_targets dpe_profile_p384_sha384
lint_rust_targets dpe_profile_p384_sha384
test_rust_targets dpe_profile_p384_sha384
run_verification_tests dpe_profile_p384_sha384 rustcrypto

# Build fuzz target
( cd dpe/fuzz
  rustup toolchain install nightly-2025-07-08
  cargo +nightly-2025-07-08 install cargo-fuzz cargo-afl --locked
  cargo fmt --check
  cargo clippy --features libfuzzer-sys
  cargo clippy --features afl
  cargo +nightly-2025-07-08 fuzz build --features libfuzzer-sys
  cargo +nightly-2025-07-08 afl build --features afl
)

# Fix license headers
ci-tools/file-header-fix.sh --check
