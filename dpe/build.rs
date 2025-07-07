// Licensed under the Apache-2.0 license
extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let default_value: usize = 24;

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let arbitrary_max_handles = env::var("ARBITRARY_MAX_HANDLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_value);

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = format!("{}/arbitrary_max_handles.rs", out_dir);

    println!("cargo:rerun-if-env-changed=ARBITRARY_MAX_HANDLES");
    println!("cargo:rerun-if-changed=build.rs");

    let max_handles_str = format!("pub const MAX_HANDLES: usize = {};", arbitrary_max_handles);

    let dest_path = PathBuf::from(&dest_path);
    match std::fs::read_to_string(&dest_path) {
        // arbitrary_max_handles.rs already exists with the data we want.
        Ok(handles) if handles.contains(&max_handles_str) => (),
        _ => std::fs::write(&dest_path, max_handles_str).unwrap(),
    }
    println!("cargo:rerun-if-changed={}", dest_path.display());

    let header_out_file = PathBuf::from(&crate_dir)
        .join("include")
        .join("caliptra_dpe.h");
    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(header_out_file);

    println!("cargo:rerun-if-changed=cbindgen.toml");
}
