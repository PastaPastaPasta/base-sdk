# An FHS layout like that of standard (non-NixOS) Linux distributions

{ pkgs, lib }:

let
  # `toolchains_llvm` reads the host's distribution from `/etc/os-release`,
  # which an image may lack. The environment's copy wins over the host's, so
  # every Linux host looks alike.
  osRelease = pkgs.writeTextDir "etc/os-release" ''
    ID=linux
    NAME="FHS environment"
  '';

  run = pkgs.buildFHSEnv {
    name = "fhs-run";
    targetPkgs = p: [
      osRelease
      p.bash
      p.bzip2
      p.coreutils
      p.diffutils
      p.file
      p.findutils
      p.gawk
      p.gnugrep
      p.gnused
      p.gnutar
      p.gzip
      # LLVM's Linux releases link `libxml2.so.2`, a soname 2.14 retired.
      p.libxml2_13
      p.ncurses
      # The C and C++ runtimes a binary built against glibc expects.
      p.stdenv.cc.cc.lib
      p.unzip
      p.which
      p.xz
      p.zlib
      p.zstd
    ];
    runScript = "env";
  };
in
{
  packages = lib.optional pkgs.stdenv.hostPlatform.isLinux run;
}
