# LLVM C(++) compiler setup and configuration

{
  pkgs,
  lib,
  llvm,
  xcodeSdk ? null,
}:

let
  # clang -print-resource-dir names the main output, but the builtin headers are
  # split into .lib, so the flag has to be passed explicitly.
  resourceDir = "${import ./compiler_rt.nix { inherit pkgs llvm; }}/lib/clang/20";

  # --ld-path names lld directly, where -fuse-ld=lld would find the nixpkgs
  # bintools wrapper on PATH. Mach-O needs ld64.
  ldFor = flavour: "--ld-path=${llvm.lld}/bin/${flavour}";

  # Per-target definitions keyed against `hostTriple`
  defs = {
    "aarch64-apple-darwin" = {
      clangTarget = "arm64-apple-darwin";
      kind = "darwin";
    };
    "x86_64-apple-darwin" = {
      clangTarget = "x86_64-apple-darwin";
      kind = "darwin";
    };
    "aarch64-unknown-linux-gnu" = {
      clangTarget = "aarch64-unknown-linux-gnu";
      kind = "glibc";
      cross = pkgs.pkgsCross.aarch64-multiplatform;
    };
    "x86_64-unknown-linux-gnu" = {
      clangTarget = "x86_64-unknown-linux-gnu";
      kind = "glibc";
      cross = pkgs.pkgsCross.gnu64;
    };
    "x86_64-pc-windows-gnu" = {
      clangTarget = "x86_64-w64-mingw32";
      kind = "mingw";
      cross = pkgs.pkgsCross.mingwW64;
    };
  };

  # MinGW keeps its headers and import libs apart, and libgcc comes from the
  # cross GCC's libraries without its driver ever being invoked. clang emits
  # crt2.o as a bare name, so -B is needed as well as -L.
  mingwFlags =
    d:
    let
      gccLib = "${d.cross.stdenv.cc.cc}/lib/gcc/x86_64-w64-mingw32/${d.cross.stdenv.cc.cc.version}";
    in
    [
      "-isystem ${d.cross.windows.mingw_w64_headers}/include"
      "-B${d.cross.windows.mingw_w64}/lib"
      "-B${gccLib}"
      "-L${d.cross.windows.mingw_w64}/lib"
      "-L${gccLib}"
      # rustc's windows-gnu spec links -l:libpthread.a by that literal name,
      # and rust-std ships no self-contained copy of it.
      "-L${d.cross.windows.pthreads}/lib"
      (ldFor "ld.lld")
    ];

  # glibc splits its outputs, so there isn't a unified tree to hand --sysroot
  # headers are in .dev, crt objects and libraries are in .out. libgcc_s.so
  # is a third output independent of the compiler's libraries.
  glibcFlags =
    d:
    let
      gccLib = "${d.cross.stdenv.cc.cc}/lib/gcc/${d.clangTarget}/${d.cross.stdenv.cc.cc.version}";
    in
    [
      "-isystem ${d.cross.stdenv.cc.libc.dev}/include"
      "-B${d.cross.stdenv.cc.libc.out}/lib"
      "-B${gccLib}"
      "-L${d.cross.stdenv.cc.libc.out}/lib"
      "-L${gccLib}"
      "-L${d.cross.stdenv.cc.cc.libgcc}/lib"
      (ldFor "ld.lld")
    ];

  darwinFlags =
    _:
    [
      "-isysroot ${xcodeSdk.sysroot}"
      "-nostdlibinc"
      "-iwithsysroot/usr/include"
      "-iframeworkwithsysroot/System/Library/Frameworks"
      "-mmacos-version-min=${xcodeSdk.minVersion}"
      (ldFor "ld64.lld")
    ]
    ++ lib.optionals (!pkgs.stdenv.hostPlatform.isDarwin) [
      "-mlinker-version=${xcodeSdk.linkerVersion}"
      "-Wl,-no_adhoc_codesign"
    ];

  # libstdc++ comes from the cross GCC rather than from the sysroot
  libStdCxx =
    d:
    let
      cc = d.cross.stdenv.cc.cc;
      inc = "${cc}/include/c++/${cc.version}";
    in
    [
      "-isystem ${inc}"
      "-isystem ${inc}/${d.clangTarget}"
      "-L${cc}/${d.clangTarget}/lib"
    ];

  # libstdc++ here was built with the mcf threading model, not the winpthreads
  # rustc asks for, so it needs mcfgthread's headers and _MCF_* symbols. gcc
  # names the library through its spec file; clang has none, so it is here.
  mingwLibStdCxx =
    d:
    libStdCxx d
    ++ [
      "-isystem ${d.cross.windows.mcfgthreads.dev}/include"
      "-L${d.cross.windows.mcfgthreads}/lib"
      "-lmcfgthread"
    ];

  # libc++ is part of the SDK, which carries its headers and its link stub.
  # These precede the C headers, since libc++ resolves its own <stddef.h>
  # first and errors out if it cannot.
  libCxx = _: [ "-iwithsysroot/usr/include/c++/v1" ];

  cxxExtra =
    d:
    {
      darwin = libCxx;
      glibc = libStdCxx;
      mingw = mingwLibStdCxx;
    }
    .${d.kind}
      d;

  flagsFor =
    d:
    {
      mingw = mingwFlags;
      glibc = glibcFlags;
      darwin = darwinFlags;
      wasm = _: [ ];
    }
    .${d.kind}
      d;

  # rustc shells out to <target>-dlltool for the raw-dylib imports windows-sys
  # declares, and looks for that exact name, not llvm-dlltool. Every binary in
  # this package is target-prefixed, so none of it shadows a host tool.
  extraPkgs = d: lib.optionals (d.kind == "mingw") [ d.cross.stdenv.cc.bintools.bintools ];

  # A driver per target and language. C_INCLUDE_PATH and CPLUS_INCLUDE_PATH
  # are unset because the host's include paths would otherwise leak into a
  # cross compile.
  driver =
    name: bin: d: extra:
    pkgs.writeShellScriptBin name ''
      exec env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
        ${llvm.clang-unwrapped}/bin/${bin} \
        --target=${d.clangTarget} \
        -resource-dir=${resourceDir} \
        ${lib.concatStringsSep " \\\n        " (extra ++ flagsFor d)} \
        "$@"
    '';

  # wasm32 has no libc or sysroot, and rustc links it with its own rust-lld,
  # so a C driver is all it needs. The cc-wrapper is bypassed because its
  # hardening flags are not supported on wasm32.
  wasmDriver =
    t:
    driver "${t}-cc" "clang" {
      clangTarget = t;
      kind = "wasm";
    } [ ];

  # `cc-rs` and `cargo` spell the same target differently.
  ccKey = t: builtins.replaceStrings [ "-" ] [ "_" ] t;
  cargoKey = t: lib.toUpper (ccKey t);

  defFor = t: defs.${t} or (throw "cxx.nix knows no C toolchain for ${t}");

  wire =
    t:
    let
      d = defFor t;
      cc = driver "${t}-cc" "clang" d [ ];
      cxx = driver "${t}-c++" "clang++" d (cxxExtra d);
    in
    {
      packages = [
        cc
        cxx
      ]
      ++ extraPkgs d;
      env = {
        "CC_${ccKey t}" = "${cc}/bin/${t}-cc";
        "CXX_${ccKey t}" = "${cxx}/bin/${t}-c++";
        "AR_${ccKey t}" = "${llvm.bintools-unwrapped}/bin/llvm-ar";
        "CARGO_TARGET_${cargoKey t}_LINKER" = "${cc}/bin/${t}-cc";
      };
    };
in
{
  # Adding clang to packages would not displace the cc-wrapper the default
  # stdenv puts on PATH, so the shell is built against this stdenv instead.
  compiler = {
    stdenv = pkgs.overrideCC pkgs.stdenv llvm.clang;
    packages = [ llvm.bintools ];
  };

  # attrNames does not force the values, so listing targets is cheap even
  # though each entry reaches for a pkgsCross set.
  knownTargets = builtins.attrNames defs;

  forTargets =
    targets:
    let
      wired = map wire targets;

      # `rustc` asks `xcrun` for the SDK and picks its own deployment target, so
      # both are set shell-wide rather than per target. A native macOS build
      # has to resolve against the same pinned SDK as a cross target.
      darwin = lib.optionalAttrs (lib.any (t: (defFor t).kind == "darwin") targets) {
        MACOS_SDK_VERSION = xcodeSdk.sdkVersion;
        MACOSX_DEPLOYMENT_TARGET = xcodeSdk.minVersion;
        SDKROOT = xcodeSdk.sysroot;
      };
    in
    {
      packages = lib.concatMap (w: w.packages) wired;
      env = lib.foldl' (a: w: a // w.env) darwin wired;
    };

  forWasm =
    targets:
    let
      cc = map wasmDriver targets;
    in
    {
      packages = cc;
      env = lib.foldl' (a: b: a // b) { } (
        lib.zipListsWith (t: c: {
          "CC_${ccKey t}" = "${c}/bin/${t}-cc";
          "AR_${ccKey t}" = "${llvm.bintools-unwrapped}/bin/llvm-ar";
        }) targets cc
      );
    };
}
