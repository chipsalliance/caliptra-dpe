{
  description = "Development environment for caliptra-dpe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustup
            go
            golint
            uv
            openssl
            pkg-config
            taplo
            cargo-nextest
          ];
          shellHook = ''
            # Ensure the toolchains are installed
            rustup toolchain install $(grep channel rust-toolchain.toml | cut -d'"' -f2)
            
            export DPE_FUZZ_TOOLCHAIN="nightly-2025-07-08"
            rustup toolchain install $DPE_FUZZ_TOOLCHAIN
            rustup target add riscv32imc-unknown-none-elf

            # Install fuzzer tools
            cargo +$DPE_FUZZ_TOOLCHAIN install cargo-fuzz --version 0.13.1 --locked
            cargo +$DPE_FUZZ_TOOLCHAIN install cargo-afl --version 0.17.0 --locked
          '';
        };
      }
    );
}
