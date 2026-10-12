set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

python := if os() == "windows" { "python" } else { "python3" }

# `[env]` attribute unavailable on just 1.40 packaged with Debian trixie
# (see https://packages.debian.org/trixie/just)
export RUSTDOCFLAGS := "-D warnings"

nextest := "cargo nextest run --config-file .cargo/nextest.toml"

[private]
default:
    @just --list

bench:
    cargo bench --workspace --features full

build:
    cargo build --workspace --features full
    cargo build --workspace --no-default-features

comb:
    {{ python }} contrib/git_filter.py --fast-fail --env NEXTEST_PROFILE=fail-fast develop HEAD -- just test lint

lint:
    @just --fmt --check
    {{ python }} maint/lint_all.py --exclude lint_codeql
    {{ python }} maint/lint/lint_codeql.py check
    {{ python }} maint/lint/lint_codeql.py run --lang=rust --with-suite=rust-security-and-quality

[positional-arguments]
[unix]
mutants *args:
    cargo mutants "$@"

[windows]
mutants *args:
    cargo mutants {{ args }}

sh:
    nix develop ./contrib/nix#dev

preview:
    {{ python }} docs/build_docs.py preview

test:
    cargo clippy --all-targets --no-default-features -- -D warnings
    cargo clippy --all-targets --features full -- -D warnings
    cargo clippy --all-targets --features full,portable -- -D warnings
    {{ nextest }} --workspace --features full
    cargo test --doc --workspace --features full
    cargo doc --workspace --no-deps --features full
    cargo test --workspace --features full --benches
