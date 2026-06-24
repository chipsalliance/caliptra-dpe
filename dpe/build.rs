// Licensed under the Apache-2.0 license

use std::env;
use std::path::PathBuf;

/// Default MAX_HANDLES when the `arbitrary_max_handles` feature is NOT enabled.
/// Must match the hardcoded constant in `dpe/src/lib.rs`.
const DEFAULT_MAX_HANDLES: usize = 64;
const DEFAULT_ARBITRARY_MAX_HANDLES: usize = 24;

const MLDSA_BASE: usize = 12307;
const MLDSA_HANDLE: usize = 158;

const P256_BASE: usize = 643;
const P256_HANDLE: usize = 126;

const P384_BASE: usize = 756;
const P384_HANDLE: usize = 159;

fn main() {
    let is_arbitrary = env::var("CARGO_FEATURE_ARBITRARY_MAX_HANDLES").is_ok();

    let max_handles = if is_arbitrary {
        env::var("ARBITRARY_MAX_HANDLES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_ARBITRARY_MAX_HANDLES)
    } else {
        DEFAULT_MAX_HANDLES
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-env-changed=ARBITRARY_MAX_HANDLES");
    println!("cargo:rerun-if-changed=build.rs");

    let max_handles_str = format!("pub const MAX_HANDLES: usize = {};", max_handles);
    let handles_path = PathBuf::from(format!("{}/max_handles.rs", out_dir));

    write_if_changed(&handles_path, &max_handles_str);
    println!("cargo:rerun-if-changed={}", handles_path.display());

    let is_ml_dsa = env::var("CARGO_FEATURE_ML_DSA").is_ok();
    let is_p256 = env::var("CARGO_FEATURE_P256").is_ok();

    let (base, per_handle): (usize, usize) = if is_ml_dsa {
        (MLDSA_BASE, MLDSA_HANDLE)
    } else if is_p256 {
        (P256_BASE, P256_HANDLE)
    } else {
        // P384
        (P384_BASE, P384_HANDLE)
    };

    // The response structs (for example CertifyKeyP384Resp) contain [u8; MAX_CERT_SIZE]
    // followed by u32 fields, and `zerocopy::IntoBytes` requires no padding.
    let max_cert_size: usize = (base + per_handle * max_handles).next_multiple_of(4);

    let max_cert_size_str = format!("const MAX_CERT_SIZE: usize = {};", max_cert_size);
    let cert_size_path = PathBuf::from(format!("{}/max_cert_size.rs", out_dir));
    write_if_changed(&cert_size_path, &max_cert_size_str);
    println!("cargo:rerun-if-changed={}", cert_size_path.display());
}

fn write_if_changed(path: &PathBuf, content: &str) {
    match std::fs::read_to_string(path) {
        Ok(existing) if existing.contains(content) => (),
        _ => std::fs::write(path, content).unwrap(),
    }
}
