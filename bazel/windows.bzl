"""A MinGW-w64 sysroot assembled from MSYS2's `mingw64` packages."""

# What a sandboxed action may read. The GCC package also carries the Windows
# build of GCC itself, which only bloats the inputs, so it goes.
_SYSROOT_BUILD = """\
filegroup(
    name = "sysroot",
    srcs = glob([
        "include/**",
        "lib/**",
    ]),
    visibility = ["//visibility:public"],
)
"""

def _msys2_sysroot_impl(rctx):
    for url, sha256 in rctx.attr.packages.items():
        rctx.download_and_extract(url = url, sha256 = sha256, type = "tar.zst")
    for path in ["mingw64/bin", "mingw64/libexec", "mingw64/share"]:
        rctx.delete(path)
    rctx.file("mingw64/BUILD.bazel", _SYSROOT_BUILD)
    rctx.file("BUILD.bazel", "")

    return rctx.repo_metadata(reproducible = True)

msys2_sysroot = repository_rule(
    implementation = _msys2_sysroot_impl,
    attrs = {
        "packages": attr.string_dict(
            mandatory = True,
            doc = "The sha256 of each package, keyed by its URL.",
        ),
    },
    doc = "Unpacks MSYS2 `mingw64` packages into one sysroot.",
)
