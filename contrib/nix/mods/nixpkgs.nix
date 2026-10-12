# Native packages sourced from the Nix Packages collection (nixpkgs)

{ pkgs }:

let
  # nixpkgs builds `zensical` against its own interpreter, which lacks
  # `pygments-styles`, needs to be supplied manually.
  pygmentsStyles = pkgs.python3Packages.buildPythonPackage {
    pname = "pygments-styles";
    version = "0.3.0";
    format = "wheel";

    src = pkgs.fetchurl {
      url = "https://files.pythonhosted.org/packages/8f/64/7e0266f0c541e26df86c31d2add9be3dd9914ae83785ce0aba7cbb693667/pygments_styles-0.3.0-py3-none-any.whl";
      hash = "sha256-xsRemTnrdZA0W8kIQRO6xGxF8SsAnRNCK+AugOhKA0w=";
    };

    dependencies = [ pkgs.python3Packages.pygments ];
  };

  zensical = pkgs.zensical.overridePythonAttrs (old: {
    dependencies = old.dependencies ++ [ pygmentsStyles ];
  });
in
{
  packages = [
    pkgs.cargo-deny
    pkgs.cargo-hack
    pkgs.cargo-llvm-cov
    pkgs.cargo-mutants
    pkgs.cargo-nextest
    pkgs.git
    pkgs.just
    pkgs.just-lsp
    pkgs.nixfmt
    pkgs.nodejs_24
    pkgs.wasm-pack

    # Packages synced with '.tools' from 'pyproject.toml'.
    pkgs.ruff
    pkgs.semgrep
    pkgs.taplo
    zensical
  ];
}
