# CodeQL CLI

{ pkgs, fhs }:

let
  inherit (pkgs) lib stdenv;

  version = "2.27.0";

  # GitHub's archive for each host, named by the directory under `tools/` that
  # holds its native binaries. The universal `codeql.zip` lacks `linux-arm64`.
  osx64 = {
    name = "osx64";
    hash = "sha256-47H7FQy/67sZvgSTAAgXfoGKxChL1khLaLqxanHFd7c=";
  };
  archives = {
    "aarch64-darwin" = osx64;
    "x86_64-darwin" = osx64;
    "aarch64-linux" = {
      name = "linux-arm64";
      hash = "sha256-PdJozYk3zs+vRH0OwIJawGrCuatVd7huzACGIViVN/0=";
    };
    "x86_64-linux" = {
      name = "linux64";
      hash = "sha256-L87sPrfRSYfCjjZqv1V7L7diZoL+LG5HbWSMqIeZCEE=";
    };
  };

  archive =
    archives.${stdenv.hostPlatform.system}
      or (throw "codeql: no archive for ${stdenv.hostPlatform.system}");
in
{
  packages = [
    (stdenv.mkDerivation {
      pname = "codeql";
      inherit version;

      src = pkgs.fetchzip {
        url = "https://github.com/github/codeql-cli-binaries/releases/download/v${version}/codeql-${archive.name}.zip";
        inherit (archive) hash;
      };

      dontConfigure = true;
      dontBuild = true;
      dontStrip = true;

      # CodeQL searches the parent of its distribution for packs, so the tree
      # sits in `$out/codeql` to keep that parent from being the whole store.
      installPhase = ''
        mkdir -p $out/{codeql,bin}
        cp -R * $out/codeql/
        ${lib.optionalString stdenv.hostPlatform.isLinux ''
          tools=$out/codeql/tools/${archive.name}
          # The tracer preloads `libtrace.so`; `linux-arm64` names it otherwise.
          [ -e $tools/libtrace.so ] || ln -s $tools/lib64trace.so $tools/libtrace.so
          # The extractors find Java through the tools directory, and the
          # bundled one expects an FHS loader, so nixpkgs' Java stands in.
          rm -rf $tools/java
          ln -s ${pkgs.jdk21} $tools/java
          # The native extractors expect an FHS loader and glibc, so the CLI
          # and every tool it spawns run inside `fhs-run`.
          printf '#!%s\nexec %s %s "$@"\n' ${stdenv.shell} \
            ${fhs.run}/bin/fhs-run $out/codeql/codeql > $out/bin/codeql
          chmod +x $out/bin/codeql
        ''}
        ${lib.optionalString (!stdenv.hostPlatform.isLinux) ''
          ln -s $out/codeql/codeql $out/bin/
        ''}
      '';

      meta = {
        description = "Semantic code analysis engine";
        homepage = "https://codeql.github.com";
        license = lib.licenses.unfree;
        platforms = lib.attrNames archives;
      };
    })
  ];
}
