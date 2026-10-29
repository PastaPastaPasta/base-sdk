"""The workspace's Rust edition, profiles, target flags and supported hosts."""

# Matches `workspace.package.edition`.
RUST_EDITION = "2021"

# Mirrors `[profile.dev]` and `[profile.release]`, with each of Cargo's
# defaults spelled out. Keyed on the Cargo profile `BUILD_PROFILES` names.
PROFILE_RUSTC_FLAGS = {
    "debug": [
        "-Ccodegen-units=256",
        "-Cdebug-assertions=yes",
        "-Cdebuginfo=2",
        "-Copt-level=0",
        "-Coverflow-checks=yes",
        "-Cpanic=unwind",
        "-Cstrip=none",
    ],
    "release": [
        "-Ccodegen-units=1",
        "-Cdebug-assertions=no",
        "-Cdebuginfo=0",
        "-Clto=fat",
        "-Copt-level=3",
        "-Coverflow-checks=no",
        "-Cpanic=abort",
        "-Cstrip=symbols",
    ],
}

# Mirrors the per-architecture `rustflags` in `.cargo/config.toml`.
TARGET_RUSTC_FLAGS = {
    "aarch64": ["-Ctarget-feature=+aes"],
    "x86_64": [
        "-Ctarget-cpu=x86-64-v3",
        "-Ctarget-feature=+adx,+aes",
    ],
}

# Each `//bazel` profile, keyed by its name, with the Cargo profile it mirrors
# and whether it builds with `TARGET_RUSTC_FLAGS`. Without them, rustc's
# defaults for the target apply.
BUILD_PROFILES = {
    "debug": ("debug", True),
    "portable_debug": ("debug", False),
    "portable_release": ("release", False),
    "release": ("release", True),
}

# Every supported host, keyed by the name its toolchain sets start with.
HOST_TRIPLES = {
    "rust_linux_aarch64": "aarch64-unknown-linux-gnu",
    "rust_linux_x86_64": "x86_64-unknown-linux-gnu",
    "rust_macos_aarch64": "aarch64-apple-darwin",
    "rust_macos_x86_64": "x86_64-apple-darwin",
}
