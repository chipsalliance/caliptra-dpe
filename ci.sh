# Licensed under the Apache-2.0 license

#!/bin/sh
set -ex

# TODO: Support building the simulator for different profiles
function build_rust_targets() {
  profile=$1

  cargo build --release --manifest-path crypto/Cargo.toml --no-default-features
  cargo build --release --manifest-path platform/Cargo.toml --features=$profile --no-default-features
  cargo build --release --manifest-path dpe/Cargo.toml --features=$profile --no-default-features
  cargo build --release --manifest-path simulator/Cargo.toml --features=$profile,openssl --no-default-features
  cargo build --release --manifest-path tools/Cargo.toml --features=$profile --no-default-features

  cargo build --manifest-path crypto/Cargo.toml --no-default-features
  cargo build --manifest-path platform/Cargo.toml --features=$profile --no-default-features
  cargo build --manifest-path dpe/Cargo.toml --features=$profile --no-default-features
  cargo build --manifest-path simulator/Cargo.toml --features=$profile,openssl --no-default-features
  cargo build --manifest-path tools/Cargo.toml --features=$profile --no-default-features

  cargo clippy --manifest-path crypto/Cargo.toml --no-default-features -- --deny=warnings
  cargo clippy --manifest-path platform/Cargo.toml --features=$profile --no-default-features -- --deny=warnings
  cargo clippy --manifest-path dpe/Cargo.toml --features=$profile --no-default-features -- --deny=warnings
  cargo clippy --manifest-path simulator/Cargo.toml --features=$profile,openssl --no-default-features -- --deny=warnings
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

  cargo test --manifest-path platform/Cargo.toml --features=$profile --no-default-features
  cargo test --manifest-path crypto/Cargo.toml --no-default-features
  cargo test --manifest-path dpe/Cargo.toml --features=$profile --no-default-features
  cargo test --manifest-path simulator/Cargo.toml --features=$profile,openssl --no-default-features
}

# TODO: Support building the simulator for different profiles
function run_verification_tests() {
  profile=$1
  crypto=$2

  cargo build --manifest-path simulator/Cargo.toml --features=$profile,$crypto --no-default-features

  ( cd verification
    go test -v
  )
}

format_rust_targets
format_go_targets

# Run tests for P256 profile
build_rust_targets dpe_profile_p256_sha256
test_rust_targets dpe_profile_p256_sha256
run_verification_tests dpe_profile_p256_sha256 openssl
run_verification_tests dpe_profile_p256_sha256 rustcrypto

# Run tests for P384 profile
build_rust_targets dpe_profile_p384_sha384
test_rust_targets dpe_profile_p384_sha384
run_verification_tests dpe_profile_p384_sha384 openssl
run_verification_tests dpe_profile_p384_sha384 rustcrypto

# Build fuzz target
( cd dpe/fuzz
  rustup toolchain install nightly-2023-04-15
  cargo +nightly-2023-04-15 install cargo-fuzz cargo-afl
  cargo fmt --check
  cargo clippy --features libfuzzer-sys
  cargo clippy --features afl
  cargo +nightly-2023-04-15 fuzz build --features libfuzzer-sys
  cargo +nightly-2023-04-15 afl build --features afl
)

# Fix license headers
ci-tools/file-header-fix.sh --check
