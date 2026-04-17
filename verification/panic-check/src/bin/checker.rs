// Licensed under the Apache-2.0 license

use std::path::PathBuf;
use std::process::ExitCode;

mod symbol_checker {
    use elf::endian::LittleEndian;
    use std::fs;
    use std::path::PathBuf;

    /// Check if the symbol table of the ELF binary provided by [path] contains one
    /// of the `&str` needles to be found in the haystack.
    /// As soon as one match is found the function returns `true`.
    /// If none of the symbols in [needles] can be found in the binary, this function
    /// returns `false`.
    pub fn elf_sym_contain_one_of(
        path: PathBuf,
        needles: Vec<&str>,
    ) -> Result<bool, anyhow::Error> {
        let elf: Vec<u8> = fs::read(&path)?;
        let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(&elf[..])?;

        if let Some((symbols, strings)) = elf.symbol_table().map_err(|e| anyhow::anyhow!("{e}"))? {
            for sym in symbols {
                let sym_name = strings.get(sym.st_name as usize)?;
                if needles.iter().any(|needle| sym_name.contains(needle)) {
                    println!("Found panic symbol: {sym_name}");
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;
        use std::env;

        #[test]
        fn test_symbol_contain() {
            let elf = env::args().next().unwrap();

            // we can assume that the mangler leaves the function name recognizable.
            // Since this executes it has to be in the binary.
            assert!(
                elf_sym_contain_one_of(PathBuf::from(&elf), vec!["test_symbol_contain"]).unwrap()
            );
            assert!(elf_sym_contain_one_of(
                PathBuf::from(&elf),
                vec!["test_symbol_contain", "DUMMY_NOT_A_SYMBOL"]
            )
            .unwrap());

            assert!(
                !elf_sym_contain_one_of(PathBuf::from(&elf), vec!["DUMMY_NOT_A_SYMBOL"]).unwrap()
            );
        }
    }
}

const PANIC_SYMBOLS: &[&str] = &[
    "panic",
    "unwrap",
    "expect",
    "slice_index",
    "panic_bounds_check",
    "panicking",
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-firmware-elf>", args[0]);
        eprintln!();
        eprintln!("Checks if the firmware ELF contains panic-related symbols.");
        eprintln!("Returns exit code 0 if no panic symbols found, 1 otherwise.");
        return ExitCode::FAILURE;
    }

    let elf_path = PathBuf::from(&args[1]);
    if !elf_path.exists() {
        eprintln!("Error: File not found: {}", elf_path.display());
        return ExitCode::FAILURE;
    }

    println!("Checking {} for panic symbols...", elf_path.display());
    match symbol_checker::elf_sym_contain_one_of(elf_path, PANIC_SYMBOLS.to_vec()) {
        Ok(true) => {
            eprintln!("FAIL: Panic symbols found in binary!");
            ExitCode::FAILURE
        }
        Ok(false) => {
            println!("PASS: No panic symbols found.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error analyzing ELF: {e}");
            ExitCode::FAILURE
        }
    }
}
