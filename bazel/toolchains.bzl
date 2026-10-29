"""Declares the workspace's Rust toolchains and the host tools of `crate_universe`.

A module file cannot load the definitions in `rustc.bzl` and `workspace.bzl`,
so this extension does. The repository rules it calls are private to rules_rust.
"""

load("@rules_rust//rust/platform:triple.bzl", "get_host_triple")

# buildifier: disable=bzl-visibility
load("@rules_rust//rust/private:repositories.bzl", "rust_repository_set", "rust_toolchain_tools_repository")

# buildifier: disable=bzl-visibility
load("@rules_rust//rust/private:repository_utils.bzl", "toolchain_repository_hub")
load(":rustc.bzl", "RUST_SHA256S", "RUST_VERSION")
load(":workspace.bzl", "HOST_TRIPLES", "PROFILE_RUSTC_FLAGS", "RUST_EDITION", "TARGET_RUSTC_FLAGS")

def _rust_toolchains_impl(module_ctx):
    # One set per supported host and profile. Toolchain flags reach every crate
    # built for the target. An empty `rustfmt_version` drops rustfmt.
    toolchains = {}
    for name, triple in HOST_TRIPLES.items():
        for profile, flags in PROFILE_RUSTC_FLAGS.items():
            toolchains.update(rust_repository_set(
                name = "{}_{}".format(name, profile),
                edition = RUST_EDITION,
                exec_triple = triple,
                extra_rustc_flags = TARGET_RUSTC_FLAGS[triple.split("-")[0]] + flags,
                rustfmt_version = "",
                sha256s = RUST_SHA256S,
                target_settings = [str(Label("//bazel:build_profile_" + profile))],
                versions = [RUST_VERSION],
            ))

    # Lets `register_toolchains` name every set at once.
    toolchain_repository_hub(
        name = "dash_rust_toolchains",
        exec_compatible_with = {k: v["exec_compatible_with"] for k, v in toolchains.items()},
        target_compatible_with = {k: v["target_compatible_with"] for k, v in toolchains.items()},
        target_settings = {k: v["target_settings"] for k, v in toolchains.items()},
        toolchain_labels = {k: v["tools_toolchain_label"] for k, v in toolchains.items()},
        toolchain_names = list(toolchains),
        toolchain_types = {k: v["toolchain_type"] for k, v in toolchains.items()},
    )

    # `crate_universe` runs cargo from these tools to resolve the graph, and
    # would otherwise fetch rules_rust's own default release.
    host = get_host_triple(module_ctx).str
    rust_toolchain_tools_repository(
        name = "rust_host_tools_pinned",
        exec_triple = host,
        rustfmt_version = "",
        sha256s = RUST_SHA256S,
        target_triple = host,
        version = RUST_VERSION,
    )

    return module_ctx.extension_metadata(reproducible = True)

rust_toolchains = module_extension(
    implementation = _rust_toolchains_impl,
    arch_dependent = True,
    doc = "The workspace's Rust toolchains, one set per host and profile.",
    os_dependent = True,
)
