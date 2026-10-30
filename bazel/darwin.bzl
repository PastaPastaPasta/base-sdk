"""A macOS SDK as a sysroot, from an extracted SDK archive."""

# Read by clang, which takes the SDK version from it. Without it, binaries
# record the deployment target as their SDK version.
def _sdk_settings_json(version):
    sdk = {
        "CanonicalName": "macosx" + version,
        "DefaultDeploymentTarget": version,
        "DisplayName": "macOS " + version,
        "IsBaseSDK": "YES",
        "MaximumDeploymentTarget": version + ".99",
        "Version": version,
    }
    sdk["SupportedTargets"] = {
        "macosx": {
            "Archs": ["arm64", "arm64e", "x86_64", "x86_64h"],
            "DefaultDeploymentTarget": version,
            "LLVMTargetTripleSys": "macos",
            "LLVMTargetTripleVendor": "apple",
            "MaximumDeploymentTarget": version + ".99",
            "MinimumDeploymentTarget": "10.13",
        },
    }
    return json.encode_indent(sdk, indent = "  ") + "\n"

# The files must be declared for a sandboxed action to see them. Frameworks
# are listed one by one, as the SDK carries hundreds nothing links.
_SDK_BUILD = """\
filegroup(
    name = "sysroot",
    srcs = ["SDKSettings.json"] + glob([
        "usr/**",
    ] + [
        "System/Library/Frameworks/{{}}.framework/**".format(name)
        for name in {frameworks}
    ]),
    visibility = ["//visibility:public"],
)
"""

def _xcode_sdk_impl(rctx):
    rctx.download_and_extract(
        url = rctx.attr.urls,
        sha256 = rctx.attr.sha256,
        stripPrefix = rctx.attr.strip_prefix,
    )

    # The extract keeps links into parts of Xcode it leaves out. A dangling
    # input fails any sandboxed action, so the rule deletes such links.
    dangling = rctx.execute(["find", "-L", str(rctx.path(".")), "-type", "l"])
    for path in dangling.stdout.splitlines():
        rctx.delete(path)

    rctx.file("SDKSettings.json", _sdk_settings_json(rctx.attr.sdk_version))
    rctx.file("BUILD.bazel", _SDK_BUILD.format(frameworks = repr(rctx.attr.frameworks)))

xcode_sdk = repository_rule(
    implementation = _xcode_sdk_impl,
    attrs = {
        "frameworks": attr.string_list(
            doc = "Frameworks a sandboxed action may read.",
        ),
        "sdk_version": attr.string(
            mandatory = True,
            doc = "The macOS version of the SDK, as in `26.1`.",
        ),
        "sha256": attr.string(mandatory = True),
        "strip_prefix": attr.string(),
        "urls": attr.string_list(mandatory = True),
    },
    doc = "Fetches a macOS SDK as a sysroot.",
)
