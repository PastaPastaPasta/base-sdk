# Development shells for the Dash Base SDK

{
  description = "Development shells for the Dash Base SDK";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    nixpkgs-llvm.url = "github:NixOS/nixpkgs/3e2cf88148e732abc1d259286123e06a9d8c964a";

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
    };

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };
  };

  outputs =
    {
      nixpkgs,
      nixpkgs-llvm,
      nixpkgs-unstable,
      rust-overlay,
      ...
    }@inputs:
    let
      inherit (nixpkgs) lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      eachSystem =
        f:
        lib.genAttrs systems (
          system:
          f {
            pkgs = import nixpkgs {
              inherit system;
              config.allowUnfree = true;
              overlays = [ rust-overlay.overlays.default ];
            };
            unstable = import nixpkgs-unstable {
              inherit system;
              config.allowUnfree = true;
            };
            llvm = (import nixpkgs-llvm { inherit system; }).llvmPackages_20;
          }
        );
    in
    {
      devShells = eachSystem (
        {
          pkgs,
          unstable,
          llvm,
        }:
        let
          ctx = import ./shell/common.nix {
            inherit
              pkgs
              lib
              inputs
              llvm
              unstable
              ;
            root = ../..;
          };
          ci = import ./shell/ci.nix ctx;
        in
        {
          inherit ci;
          dev = import ./shell/dev.nix (ctx // { inherit ci; });
        }
      );

      formatter = eachSystem ({ pkgs, ... }: pkgs.nixfmt);
    };
}
