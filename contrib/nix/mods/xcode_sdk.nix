# Xcode-derived macOS SDK with libcxx headers

{ pkgs }:

let
  inherit (pkgs) lib;

  # Xcode release and build ID
  version = "26.1.1-17B100";

  sdkVersion = "26.1";

  platform = "Platforms/MacOSX.platform";
  sdks = "${platform}/Developer/SDKs";
  sdk = "${sdks}/MacOSX${sdkVersion}.sdk";

  # `xcrun` finds an SDK through the plists, which the archive lacks.
  plist =
    entries:
    pkgs.writeText "Info.plist" ''
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0"><dict>
      ${
        lib.concatStrings (
          lib.mapAttrsToList (key: value: "  <key>${key}</key><string>${value}</string>\n") entries
        )
      }</dict></plist>
    '';

  # clang reads the SDK version from `SDKSettings.json`. Without the file,
  # binaries record the deployment target as their SDK version.
  sdkSettings = pkgs.writeText "SDKSettings.json" (
    builtins.toJSON {
      CanonicalName = "macosx${sdkVersion}";
      DefaultDeploymentTarget = sdkVersion;
      DisplayName = "macOS ${sdkVersion}";
      IsBaseSDK = "YES";
      MaximumDeploymentTarget = "${sdkVersion}.99";
      Version = sdkVersion;
      SupportedTargets.macosx = {
        Archs = [
          "arm64"
          "arm64e"
          "x86_64"
          "x86_64h"
        ];
        DefaultDeploymentTarget = sdkVersion;
        LLVMTargetTripleSys = "macos";
        LLVMTargetTripleVendor = "apple";
        MaximumDeploymentTarget = "${sdkVersion}.99";
        MinimumDeploymentTarget = "10.13";
      };
    }
  );
in

pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "xcode-sdk";
  inherit version;

  # The archive holds a bare sysroot, so `installPhase` builds the
  # DEVELOPER_DIR around it.
  src = pkgs.fetchurl {
    url = "https://bitcoincore.org/depends-sources/sdks/Xcode-${version}-extracted-SDK-with-libcxx-headers.tar";
    hash = "sha256-lgD6k2RN9nTukWteLIprqNrPYxmWpl3JItADuYteo7E=";
  };

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p "$out/${sdk}" "$out/Toolchains/XcodeDefault.xctoolchain"
    cp -a ./* "$out/${sdk}/"
    ln -s "MacOSX${sdkVersion}.sdk" "$out/${sdks}/MacOSX.sdk"

    cp ${sdkSettings} "$out/${sdk}/SDKSettings.json"
    cp ${
      plist {
        CanonicalName = "macosx${sdkVersion}";
        DisplayName = "macOS ${sdkVersion}";
        IsBaseSDK = "YES";
        MaximumDeploymentTarget = "${sdkVersion}.99";
        Version = sdkVersion;
      }
    } "$out/${sdk}/SDKSettings.plist"
    cp ${
      plist {
        FamilyIdentifier = "macosx";
        FamilyName = "macOS";
        Identifier = "com.apple.platform.macosx";
        Name = "macosx";
        Type = "Platform";
        Version = sdkVersion;
      }
    } "$out/${platform}/Info.plist"
    cp ${
      plist { Identifier = "com.apple.dt.toolchain.XcodeDefault"; }
    } "$out/Toolchains/XcodeDefault.xctoolchain/ToolchainInfo.plist"

    # Apple's `xcrun` accepts a DEVELOPER_DIR only if it holds `usr/bin/xcrun`.
    ${lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
      mkdir -p "$out/usr/bin"
      ln -s ${lib.getExe' pkgs.xcbuild "xcrun"} "$out/usr/bin/xcrun"
    ''}

    runHook postInstall
  '';

  # The fixup phase would treat target Mach-O stubs as host binaries.
  dontFixup = true;

  passthru = {
    # `$out` is a DEVELOPER_DIR, so the sysroot is named separately.
    sysroot = "${finalAttrs.finalPackage}/${sdk}";
    inherit sdkVersion;
    # The target deployment version (i.e. minimum macOS version).
    minVersion = "14.0";
    # lld is not ld64, and clang gates linker flags on its version.
    linkerVersion = "711";
  };

  meta = {
    description = "macOS SDK extracted from Xcode, with libc++ headers";
    license = lib.licenses.unfree;
  };
})
