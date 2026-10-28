# Bazel through bazelisk, with buildifier.

{ pkgs }:

let
  # nixpkgs builds Bazel from source, whose lockfiles differ from those of the
  # release binaries. Bazelisk fetches the release hosts without Nix run too.
  bazelisk = pkgs.writeShellScriptBin "bazel" ''
    exec ${pkgs.bazelisk}/bin/bazelisk "$@"
  '';
in
{
  packages = [
    bazelisk
    pkgs.buildifier
  ];

  shellHook = ''
    if root=$(git rev-parse --show-toplevel 2> /dev/null); then
      export BAZELISK_HOME="$root/.cache/bazelisk"
    fi
  '';
}
