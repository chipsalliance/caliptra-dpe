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
          ];

          shellHook = ''
            # Ensure the toolchains are installed
            rustup toolchain install $(grep channel rust-toolchain.toml | cut -d'"' -f2)
            rustup toolchain install nightly-2025-07-08
          '';
        };
      }
    );
}
