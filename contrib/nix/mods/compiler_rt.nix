# The clang resource directory drivers compile and link with

{ pkgs, llvm }:

let
  macos = pkgs.stdenvNoCC.mkDerivation {
    pname = "macos-compiler-rt";
    version = "20.1.3";

    src = pkgs.fetchurl {
      url = "https://conda.anaconda.org/conda-forge/noarch/compiler-rt_osx-64-20.1.3-hc6f8467_0.conda";
      hash = "sha256-DNAy1cTVF7Toej8nY599YWBlvrtLhwtXbb4+LW2Lyzc=";
    };

    nativeBuildInputs = [
      pkgs.unzip
      pkgs.zstd
    ];

    # A `.conda` package is a zip holding the payload as a zstd tarball.
    unpackPhase = ''
      runHook preUnpack
      unzip -q "$src" 'pkg-*.tar.zst'
      mkdir payload
      tar --zstd -xf pkg-*.tar.zst -C payload
      runHook postUnpack
    '';

    dontConfigure = true;
    dontBuild = true;

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -a payload/lib "$out/"
      runHook postInstall
    '';

    # The fixup phase would treat target Mach-O archives as host binaries.
    dontFixup = true;

    meta.license = llvm.compiler-rt.meta.license;
  };
in
pkgs.symlinkJoin {
  name = "clang-resource-dir";
  paths = [
    # Supplies clang's builtin headers.
    llvm.clang-unwrapped.lib
    # nixpkgs builds compiler-rt for the host alone, while conda-forge's
    # universal archives serve macOS targets from any host.
    macos
  ];
}
