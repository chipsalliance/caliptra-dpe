// Licensed under the Apache-2.0 license

use elf::endian::LittleEndian;
use std::fs;
use std::path::PathBuf;

/// Symbols whose presence in the ELF binary indicates that panics are possible.
pub const PANIC_SYMBOL: &str = "panic_is_possible";

/// Check if the symbol table of the ELF binary at [path] contains the symbol [needle].
fn elf_contains_symbol(path: PathBuf, needle: &str) -> Result<bool, anyhow::Error> {
    let elf: Vec<u8> = fs::read(&path)?;
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(&elf[..])?;

    if let Some((symbols, strings)) = elf.symbol_table().map_err(|e| anyhow::anyhow!("{e}"))? {
        for sym in symbols {
            let sym_name = strings.get(sym.st_name as usize)?;
            if sym_name == needle {
                eprintln!("found needle symbol: {sym_name}");
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Check if the ELF binary at [path] contains the panic symbol [PANIC_SYMBOL].
pub fn elf_contains_panic(path: PathBuf) -> Result<bool, anyhow::Error> {
    elf_contains_symbol(path, PANIC_SYMBOL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::hint::black_box;
    use std::process::Command;

    const RISCV_TARGET: &str = "riscv32imc-unknown-none-elf";
    /// Each entry is the feature string passed to `cargo build --features`.
    /// The `cfi` feature mirrors how xtask builds with CFI instrumentation.
    const PROFILES: &[&str] = &["ml-dsa,cfi", "p256,cfi", "p384,cfi", "hybrid,cfi"];

    fn workspace_root() -> PathBuf {
        // CARGO_MANIFEST_DIR points to verification/panic-check/checker/
        // Workspace root is three levels up.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .expect("failed to resolve workspace root")
    }

    fn firmware_manifest() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../firmware/Cargo.toml")
            .canonicalize()
            .expect("failed to resolve firmware manifest path")
    }

    fn firmware_elf_path(workspace_root: &PathBuf) -> PathBuf {
        workspace_root
            .join("target")
            .join(RISCV_TARGET)
            .join("firmware-check")
            .join("panic-check-firmware")
    }

    fn build_firmware(features: &str) {
        let manifest = firmware_manifest();
        let status = Command::new("cargo")
            .args([
                "build",
                "--manifest-path",
                manifest.to_str().unwrap(),
                "--target",
                RISCV_TARGET,
                "--profile",
                "firmware-check",
                "--no-default-features",
                "--features",
                features,
            ])
            .status()
            .expect("failed to invoke cargo build");

        assert!(
            status.success(),
            "cargo build for firmware failed with status: {status}"
        );
    }

    /// Known symbol with a stable (unmangled) name for the self-check test.
    #[unsafe(no_mangle)]
    fn _panic_check_checker_test_sym() {}

    #[test]
    fn test_elf_sym_lookup() {
        black_box(_panic_check_checker_test_sym());
        let elf = env::args().next().unwrap();
        assert!(elf_contains_symbol(PathBuf::from(&elf), "_panic_check_checker_test_sym").unwrap());
        assert!(!elf_contains_symbol(PathBuf::from(&elf), "DUMMY_NOT_A_SYMBOL").unwrap());
    }

    /// Checks that the firmware ELF at [elf_path] does **not** contain
    /// the [`PANIC_SYMBOL`].
    fn assert_no_panic_symbols(elf_path: &PathBuf) {
        assert!(
            elf_path.exists(),
            "Firmware ELF not found at: {}",
            elf_path.display()
        );
        assert!(!elf_contains_panic(elf_path.clone()).expect("failed to analyze firmware ELF"),);
    }

    /// Checks that the firmware ELF at [elf_path] **does** contain
    /// the [`PANIC_SYMBOL`].
    fn assert_has_panic_symbols(elf_path: &PathBuf) {
        assert!(
            elf_path.exists(),
            "Firmware ELF not found at: {}",
            elf_path.display()
        );
        println!(
            "Checking {} for panic symbols (should-fail)...",
            elf_path.display()
        );
        assert!(
            elf_contains_panic(elf_path.clone()).expect("failed to analyze firmware ELF"),
            "UNEXPECTED PASS: Expected panic symbols but none found. \
             The should-fail test should have detected panic symbols!"
        );
    }

    /// Builds the firmware for every crypto profile and verifies that:
    /// 1. Each clean build contains no panic symbols.
    /// 2. The `should-fail` build (hybrid) does contain panic symbols.
    #[test]
    fn test_firmware_panic_check() {
        let root = workspace_root();
        let elf_path = firmware_elf_path(&root);

        // Verify every profile is panic-free.
        for profile in PROFILES {
            println!("profile: {profile}");
            build_firmware(profile);
            assert_no_panic_symbols(&elf_path);
        }

        println!("profile: hybrid,cfi (should-fail)");
        build_firmware("hybrid,cfi,should-fail");
        assert_has_panic_symbols(&elf_path);
    }
}
