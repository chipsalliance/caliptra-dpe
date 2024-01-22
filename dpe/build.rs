// Licensed under the Apache-2.0 license

use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    let default_value: usize = 24;

    let arbitrary_max_handles = env::var("ARBITRARY_MAX_HANDLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_value);

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = format!("{}/arbitrary_max_handles.rs", out_dir);

    println!("cargo:rerun-if-env-changed=ARBITRARY_MAX_HANDLES");
    println!("cargo:rerun-if-changed=build.rs");

    let mut file = File::create(&dest_path).unwrap();
    write!(
        file,
        "pub const MAX_HANDLES: usize = {};",
        arbitrary_max_handles
    )
    .unwrap();

    println!("cargo:rerun-if-changed={}", dest_path);
}
