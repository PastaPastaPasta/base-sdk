# Bazel through bazelisk, with the buildifier release the Starlark linter pins.

{ pkgs }:

let
  inherit (pkgs) stdenv;

  # nixpkgs builds Bazel from source, whose lockfiles differ from those of the
  # release binaries. Bazelisk fetches the release hosts without Nix run too.
  bazelisk = pkgs.writeShellScriptBin "bazel" ''
    exec ${pkgs.bazelisk}/bin/bazelisk "$@"
  '';

  # Mirrors `_BUILDIFIER_VERSION` and `_BUILDIFIER_SHA256S` in `lint_bazel.py`,
  # as nixpkgs carries an older release.
  buildifierVersion = "10.1.0";
  buildifierAssets = {
    "aarch64-darwin" = {
      name = "darwin-arm64";
      hash = "sha256-6YBIZMQH+SD17L8DpeBWqBReEaaua5DSQ4o/0QbTRHM=";
    };
    "x86_64-darwin" = {
      name = "darwin-amd64";
      hash = "sha256-6eEP9S7IeG/KvM0lHIEJ6/Me974fZn4nxuBpuW29wfY=";
    };
    "aarch64-linux" = {
      name = "linux-arm64";
      hash = "sha256-ONLthF9WC0oW3e5B3pBlCKlfjchbBOCFGwpx46cNOJA=";
    };
    "x86_64-linux" = {
      name = "linux-amd64";
      hash = "sha256-Mbaoqh5cdGaWeI9ChylwF3CtkZJYc9glbLiFxg4Sx34=";
    };
  };
  buildifierAsset =
    buildifierAssets.${stdenv.hostPlatform.system}
      or (throw "buildifier: no release for ${stdenv.hostPlatform.system}");

  buildifier = stdenv.mkDerivation {
    pname = "buildifier";
    version = buildifierVersion;

    src = pkgs.fetchurl {
      url = "https://github.com/bazelbuild/buildtools/releases/download/v${buildifierVersion}/buildifier-${buildifierAsset.name}";
      inherit (buildifierAsset) hash;
    };

    dontUnpack = true;
    dontConfigure = true;
    dontBuild = true;
    dontStrip = true;

    installPhase = ''
      install -Dm755 $src $out/bin/buildifier
    '';
  };
in
{
  packages = [
    bazelisk
    buildifier
  ];

  shellHook = ''
    export BUILDIFIER=${buildifier}/bin/buildifier
    if root=$(git rev-parse --show-toplevel 2> /dev/null); then
      export BAZELISK_HOME="$root/.cache/bazelisk"
    fi
  '';
}
