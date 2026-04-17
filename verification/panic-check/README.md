# panic-check

Verify that the firmware image does not the possibily for panics.
The `firmware` profile is the same as the one in `caliptra-sw` to mimick the same build process.
The `firmware-check` profile differs in the sense, that it does not strip the symbols, such that
we can find any panic related ELF symbols.

The crate offers the feature `should-fail`, which introduces code that implicitly must lead to the
generation of a panic handler.
Thus we can verify that the detection method works and detects a true positive case.

## should-panic
```
cargo build --manifest-path verification/panic-check/Cargo.toml \
  --bin firmware \
  --target riscv32imc-unknown-none-elf \
  --profile firmware-check \
  --no-default-features \
  --features hybrid,should-fail
  
cargo run --manifest-path verification/panic-check/Cargo.toml \
  --bin checker --features std \
  -- verification/target/riscv32imc-unknown-none-elf/firmware-check/firmware
```

## shouldn't panic

```
cargo build --manifest-path verification/panic-check/Cargo.toml \
  --bin firmware \
  --target riscv32imc-unknown-none-elf \
  --profile firmware-check \
  --no-default-features \
  --features hybrid

cargo run --manifest-path verification/panic-check/Cargo.toml \
  --bin checker --features std \
  -- verification/target/riscv32imc-unknown-none-elf/firmware-check/firmware
```
