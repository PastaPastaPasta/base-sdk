"""Flags and rules shared by every Bazel-built Rust crate."""

load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_proc_macro")

# rules_rust ignores `[lints]`, so the workspace denies are restated here.
# Clippy lints are omitted, as plain rustc rejects them.
RUSTC_LINTS = [
    "-Dkeyword_idents",
    "-Dmissing_debug_implementations",
    "-Dnon_ascii_idents",
    "-Drust_2021_incompatible_closure_captures",
    "-Drust_2021_incompatible_or_patterns",
    "-Dunsafe_code",
    "-Dunused_must_use",
]

def _bool_flag_impl(_ctx):
    return []

bool_flag = rule(
    implementation = _bool_flag_impl,
    build_setting = config.bool(flag = True),
    doc = "A boolean command-line flag, read through `config_setting`.",
)

def dash_rust_library(name, crate_features, deps = [], proc_macro_deps = [], portable = False):
    """A workspace crate, built with the workspace lints.

    `crate_features`, `deps` and `proc_macro_deps` restate what the anchor
    resolves for the crate; the graph check holds them to it. A crate with a
    `portable` feature sets `portable`, which the portable profiles enable.
    """
    rust_library(
        name = name,
        srcs = native.glob(["src/**/*.rs"]),
        crate_features = crate_features + (select({
            "//bazel:profile_portable_debug": ["portable"],
            "//bazel:profile_portable_release": ["portable"],
            "//conditions:default": [],
        }) if portable else []),
        crate_name = name.replace("-", "_"),
        proc_macro_deps = all_crate_deps(proc_macro = True) + proc_macro_deps,
        rustc_flags = RUSTC_LINTS,
        visibility = ["//visibility:public"],
        deps = all_crate_deps(normal = True) + deps,
    )

def dash_rust_proc_macro(name):
    """A workspace proc macro, built with the workspace lints.

    Like Cargo, Bazel builds it for the exec platform only, as a dependency.
    `manual` keeps `//...` from also building it with the target's flags.
    """
    rust_proc_macro(
        name = name,
        srcs = native.glob(["src/**/*.rs"]),
        crate_name = name.replace("-", "_"),
        rustc_flags = RUSTC_LINTS,
        tags = ["manual"],
        visibility = ["//visibility:public"],
        deps = all_crate_deps(normal = True),
    )
