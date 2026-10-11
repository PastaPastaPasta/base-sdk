# Getting Started

> [!TIP]
> On ARM64 and AMD64 Linux and macOS hosts, we offer [development shells](./devshells.md) that provide environments
> identical to or based on environments used in CI as an alternative to manual setup. The following instructions are
> for manual setup.

## Installing Rust

> [!WARNING]
> Some platforms offer Rust through their package manager. Depending on the maintainer policy, this version may be
> well out of date relative to `stable`. `base-sdk` is only validated against its specified minimum supported Rust
> version (MSRV) and `stable`. Its pinned `nightly` serves development and linting only.
>
> Anything outside that set is untested and may result in unexpected behaviour.

It is recommended to use [`rustup`](https://rustup.rs/) to manage your Rust build environment. This guide assumes
that platform-specific instructions to install `rustup` have been followed and your `$PATH` variable has been
refreshed. Running it should print something like the following.

```console
$ rustup --version
rustup 1.29.0 (28d1352db 2026-03-05)
info: This is the version for the rustup toolchain manager, not the rustc compiler.
info: the currently active `rustc` version is `rustc 1.95.0-nightly (905b92696 2026-01-31)`
```

By default, `rustup` will read [`rust-toolchain.toml`](../../rust-toolchain.toml) and download the necessary
components at the supported versions without further intervention. Should you want to use a different
version, please consult the vendor documentation for
`RUSTUP_TOOLCHAIN` ([source](https://rust-lang.github.io/rustup/environment-variables.html)).

<!-- [include:contrib/README.md:setup] -->
