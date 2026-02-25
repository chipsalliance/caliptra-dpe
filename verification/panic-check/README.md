# panic-check

Ensure that the DPE library is free of panics by building and checking a sample firmware.
The `firmware` profile is the same as the one in `caliptra-sw` to mimick the same build process.
The `firmware-check` profile differs in the sense, that it does not strip the symbols, such that
we can find any panic related ELF symbols.

The firmware crate offers the feature `should-fail`, which introduces code that implicitly must
lead to the generation of a panic handler.
Thus we can verify that the detection method works and detects a true positive case.

## Crate structure

- **`firmware/`** -- `no_std` Binary crate targeting `riscv32imc-unknown-none-elf`. Exercises the
  DPE API so the compiler emits all reachable code paths.
- **`checker/`** -- Library crate that inspects ELF symbol tables for panic-related symbols.
  Contains a unit test (`test_firmware_panic_check`) that builds the firmware and verifies it is
  panic-free (and that the `should-fail` feature correctly introduces panic symbols).

## Running the checker test

```
cargo test -p panic-check-checker
```

This will:
1. Build the firmware for `riscv32imc-unknown-none-elf` with `--profile firmware-check`.
2. Check the resulting ELF for panic symbols (should pass).
3. Rebuild with `should-fail` and verify panic symbols are detected.

## Manual firmware build

### should-panic
```
cargo build --manifest-path verification/panic-check/firmware/Cargo.toml \
  --target riscv32imc-unknown-none-elf \
  --profile firmware-check \
  --no-default-features \
  --features hybrid,should-fail
```

### shouldn't panic
```
cargo build --manifest-path verification/panic-check/firmware/Cargo.toml \
  --target riscv32imc-unknown-none-elf \
  --profile firmware-check \
  --no-default-features \
  --features hybrid
```
