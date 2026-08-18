{
  description = "Development environment for caliptra-dpe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    mjolnir = {
      url = "github:chipsalliance/mjolnir/d53222604da502e82a41944c4b3229ce7ca69ad6";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, mjolnir, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustup
            go
            golint
            uv
            openssl
            pkg-config
            taplo
            cargo-nextest
            wasm-bindgen-cli
          ];
          shellHook = ''
            # Ensure the toolchains are installed
            rustup toolchain install $(grep channel rust-toolchain.toml | cut -d'"' -f2)
            
            export DPE_FUZZ_TOOLCHAIN="nightly-2025-07-08"
            rustup toolchain install $DPE_FUZZ_TOOLCHAIN
            rustup target add riscv32imc-unknown-none-elf
            rustup target add wasm32-unknown-unknown

            # Install fuzzer tools
            cargo +$DPE_FUZZ_TOOLCHAIN install cargo-fuzz --version 0.13.1 --locked
            cargo +$DPE_FUZZ_TOOLCHAIN install cargo-afl --version 0.17.0 --locked
          '';
        };
      in
      {
        devShells.default = devShell;

        packages = mjolnir.lib.discoverProjectJobs {
          inherit pkgs devShell;
          mjolnirApp = mjolnir.packages.${system}.mjolnir-app;
          projectDir = ./tools/mjolnir;
          deployPackages = {
            inherit (mjolnir.packages.${system}) deploy-gcs-runs;
          };
        };
      }
    );
}
