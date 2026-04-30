# caliptra-dpe

High level module that implements DPE and defines high-level traits that are
used to communicate with the crypto peripherals and PCRs

Crates:

* dpe: The DPE firmware implementation
* simulator: A userspace DPE simulator

## Development

This project uses the `xtask` pattern for common development tasks. You can run them using `cargo xtask <command>`.

### Development Environment

A Nix flake is provided to set up a consistent development environment with all necessary dependencies (Rust, Go, uv, OpenSSL, etc.).

If you have Nix installed with flakes enabled, you can enter the development environment by running:

```bash
nix develop
```

### xtask Commands

Available commands:
* `cargo xtask ci`: Run all CI checks (format, lint, test, etc.)
* `cargo xtask test`: Run all tests.
    * `cargo xtask test unit`: Run Rust unit tests.
    * `cargo xtask test verification`: Run Go verification tests.
    * `cargo xtask test certs`: Run cert parser tests.
    * `cargo xtask test generate-test-data`: Generate test certificates and keys.
    * `cargo xtask test miri --nthreads <n> (--nextest)`: Run miri tests with `n` threads (`--nextest` via nextest).
* `cargo xtask precheckin`: Run formatting, linters, and license header checks.
    * `cargo xtask precheckin headers`: Check license headers.
    * `cargo xtask precheckin format`: Check code formatting.
    * `cargo xtask precheckin lint`: Run linters.
* `cargo xtask run-tool`: Run a tool from the `tools/` folder.
    * `cargo xtask run-tool sample-dpe-cert`: Run `sample_dpe_cert`.
    * `cargo xtask run-tool cert-size`: Run `cert-size`.
