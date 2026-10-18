set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

python := if os() == "windows" { "python" } else { "python3" }

# `[env]` attribute unavailable on just 1.40 packaged with Debian trixie
# (see https://packages.debian.org/trixie/just)
export RUSTDOCFLAGS := "-D warnings"

each := "cargo hack --workspace --exclude-features default --each-feature"
powerset := "cargo hack --workspace --exclude-features default --feature-powerset"

[private]
default:
    @just --list

bench:
    cargo bench --workspace --features full

build:
    {{ each }} build

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
    {{ powerset }} clippy --all-targets -- -D warnings
    {{ each }} nextest run --config-file .cargo/nextest.toml --no-tests=warn
    {{ each }} test --doc
    cargo doc --workspace --no-deps --features full
    {{ each }} test --benches
