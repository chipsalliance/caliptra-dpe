# Tool to check for the absence of panic in the DPE implementation

This crate provides a binary target, to do a compile-time check, if specific functions of the DPE implementation can panic.

The `main` functino creates a DPE instance with dummy platform abstractions.
Dummy calls to the instance methods are then wrapped in shim functions that are checked with [no_panic](https://docs.rs/no-panic/latest/no_panic/).
For every function call that `no_panic` detects possible panics, an error is emitted when linking.

**Note:** For the code to pass `#[no_panic]`, certain optimizations are needed.
          Build with `--release` to enable necessary optimizations.
