# Common logic shared between development shells

{
  pkgs,
  lib,
  inputs,
  llvm,
  root,
  unstable,
}:

let
  # Target platform for web demos bundled with documentation.
  commonTargets = [ "wasm32-unknown-unknown" ];

  cxx = import ../mods/cxx.nix {
    inherit pkgs lib llvm;
    xcodeSdk = import ../mods/xcode_sdk.nix { inherit pkgs; };
  };

  rsComponents = (lib.importTOML (root + "/rust-toolchain.toml")).toolchain.components;

  hostTriple = pkgs.stdenv.hostPlatform.rust.rustcTarget;
  sameOs = t: lib.hasInfix (if pkgs.stdenv.hostPlatform.isDarwin then "apple-darwin" else "linux") t;
  crossTargets = lib.filter (t: t != hostTriple && sameOs t) cxx.knownTargets;

  # Everything else the table knows, which needs a sysroot of its own and so
  # only the dev shell carries.
  foreignTargets = lib.filter (t: t != hostTriple && !sameOs t) cxx.knownTargets;

  # rust-overlay propagates a C compiler wrapper with every toolchain, which
  # would take precedence over `cxx.nix`'s definitions. We strip it here so that
  # every shell reaching for a toolchain respects our definitions.
  bare =
    toolchain:
    toolchain.overrideAttrs (_: {
      propagatedBuildInputs = [ ];
      depsHostHostPropagated = [ ];
      depsTargetTargetPropagated = [ ];
    });

  nightlyWith =
    extra:
    bare (
      (pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml")).override {
        targets = commonTargets ++ extra;
      }
    );

  # Folds modules into mkShell arguments. Conflicting variables or stdenvs
  # will throw instead of allowing order-sensitive assignment.
  compose =
    mods:
    let
      named = m: m._name or "<unnamed>";
      envs = map (m: m.env or { }) mods;
      names = lib.concatMap lib.attrNames envs;
      clashes = lib.unique (lib.filter (n: lib.count (m: m == n) names > 1) names);
      chosen = lib.filter (m: (m.stdenv or null) != null) mods;
      mkShell =
        if chosen == [ ] then
          pkgs.mkShell
        else if lib.length chosen == 1 then
          pkgs.mkShell.override { stdenv = (lib.head chosen).stdenv; }
        else
          throw "stdenv redefined: ${lib.concatMapStringsSep ", " named chosen}";
    in
    if clashes != [ ] then
      throw "variables redefined: ${lib.concatStringsSep ", " clashes}"
    else
      mkShell (
        {
          packages = lib.concatMap (m: m.packages or [ ]) mods;
          shellHook = lib.concatStringsSep "\n" (lib.filter (h: h != "") (map (m: m.shellHook or "") mods));
        }
        // lib.foldl' (a: b: a // b) { } envs
      );
in
{
  inherit
    pkgs
    lib
    commonTargets
    compose
    crossTargets
    cxx
    foreignTargets
    nightlyWith
    ;

  mods = lib.mapAttrs (name: m: m // { _name = name; }) {
    bazel = import ../mods/bazel.nix { inherit pkgs; };
    codeql = import ../mods/codeql.nix { inherit pkgs unstable; };
    cxx = cxx.compiler;
    fhs = import ../mods/fhs.nix { inherit pkgs lib; };
    nixpkgs = import ../mods/nixpkgs.nix { inherit pkgs; };
    python = import ../mods/python.nix {
      inherit pkgs lib;
      inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
      workspaceRoot = root;
      # Must match `project.requires-python` in pyproject.toml, effective floor.
      python = pkgs.python311;
    };
    rust = import ../mods/rust.nix {
      inherit lib;
      default = "nightly";
      toolchains = {
        nightly = nightlyWith crossTargets;
        # Must match `workspace.package.rust-version` in root Cargo.toml.
        msrv = bare (pkgs.rust-bin.stable."1.89.0".minimal.override { extensions = rsComponents; });
      };
    };
  };
}
