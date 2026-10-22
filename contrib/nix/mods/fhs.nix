# An FHS layout like that of standard (non-NixOS) Linux distributions

{ pkgs, lib }:

let
  run = pkgs.buildFHSEnv {
    name = "fhs-run";
    targetPkgs = p: [
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
