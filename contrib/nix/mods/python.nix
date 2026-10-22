# Packages sourced from PyPI against lockfile imported with uv2nix

{
  pkgs,
  lib,
  uv2nix,
  pyproject-nix,
  pyproject-build-systems,
  workspaceRoot,
  python,
}:

let
  workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };

  # Prefer binary distributions (i.e. wheels) when we can, saves us some build
  # complexity.
  overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

  overrides = final: prev: {
    # rjsmin doesn't publish wheels for macOS. uv.lock does not track build
    # dependencies (see astral-sh/uv#5190), so we manually define 'setuptools'.
    rjsmin = prev.rjsmin.overrideAttrs (old: {
      nativeBuildInputs =
        (old.nativeBuildInputs or [ ]) ++ final.resolveBuildSystem { setuptools = [ ]; };
    });

    # `lief` links the C++ runtime, `autoPatchelfHook` has to find it for Linux.
    lief = prev.lief.overrideAttrs (old: {
      buildInputs =
        (old.buildInputs or [ ]) ++ lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.stdenv.cc.cc.lib;
    });

    # Narrow rebuild triggers to relevant files to avoid pulling in the whole
    # source tree and thrashing the cache for it.
    dash-base-sdk = prev.dash-base-sdk.overrideAttrs (_: {
      src = lib.fileset.toSource {
        root = workspaceRoot;
        fileset = lib.fileset.unions [
          (workspaceRoot + "/pyproject.toml")
          (workspaceRoot + "/uv.lock")
        ];
      };
    });
  };

  pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope (
    lib.composeManyExtensions [
      pyproject-build-systems.overlays.default
      overlay
      overrides
    ]
  );

  # '.dev' is a union of '.lib' and '.tools', '.tools' is sourced from nixpkgs.
  # Sourcing '.lib' satisfies '.dev', completing the dependency list.
  venv = pythonSet.mkVirtualEnv "dash-base-sdk-lib" { dash-base-sdk = [ "lib" ]; };
in
{
  packages = [
    venv
    pkgs.uv
  ];

  env = {
    UV_PYTHON = "${venv}/bin/python";
    UV_NO_SYNC = "1";
  };

  # `semgrep` and other Python applications place their own interpreter
  # in PATH, eclipsing our interpreter, preventing it from importing our
  # workspaces packages.
  shellHook = ''
    export PATH="${venv}/bin:$PATH"
  '';
}
