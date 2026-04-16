// Licensed under the Apache-2.0 license

use std::env;
use std::path::PathBuf;

fn main() {
    let default_issuer_name_size: usize = 128;

    let arbitrary_issuer_name_size = env::var("ARBITRARY_ISSUER_NAME_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_issuer_name_size);

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = format!("{}/arbitrary_issuer_name_size.rs", out_dir);

    println!("cargo:rerun-if-env-changed=ARBITRARY_ISSUER_NAME_SIZE");
    println!("cargo:rerun-if-changed=build.rs");

    let issuer_name_size_str = format!(
        "pub const MAX_ISSUER_NAME_SIZE: usize = {};",
        arbitrary_issuer_name_size
    );

    let dest_path = PathBuf::from(&dest_path);
    match std::fs::read_to_string(&dest_path) {
        // arbitrary_issuer_name_size.rs already exists with the data we want.
        Ok(size) if size.contains(&issuer_name_size_str) => (),
        _ => std::fs::write(&dest_path, issuer_name_size_str).unwrap(),
    }
    println!("cargo:rerun-if-changed={}", dest_path.display());
}
