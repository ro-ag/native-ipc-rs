{
  description = "native-ipc-rs Linux development and verification shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rust = pkgs.rust-bin.stable."1.97.0".minimal.override {
            extensions = [
              "clippy"
              "rustfmt"
              "rust-src"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rust
              clang
              gdb
              lsof
              pkg-config
              procps
              strace
              util-linux
            ];

            RUST_BACKTRACE = "1";
          };
        }
      );
    };
}
