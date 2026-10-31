<!-- [start:omit] -->

> [!TIP]
> In order to run these scripts, make sure you've set up a development environment as described in
> [`contrib`](../contrib/README.md)

<!-- [end:omit] -->

## Linters

All linters available are listed below. The first verb is implied if no verb is specified at runtime. Verbs may accept
arguments of their own, for more information, run an individual lint script with `--help`. To run all scripts,
use [`lint_all.py`](./lint_all.py).

| Name | Purpose | Verbs | Depends on |
| --- | --- | --- | --- |
| [`lint_commit.py`](./lint/lint_commit.py) | Lint commit names against [`commit.toml`](./commit.toml) | `run` | `git` |
| [`lint_bazel.py`](./lint/lint_bazel.py) | Lint Starlark files with `buildifier`, hold the rustc flags and edition Bazel builds with to cargo's, and the crates Bazel builds to cargo's graph | `check`, `apply`, `apply-all`, `graph` | `buildifier`, `bazel` and `cargo` (`graph`) |
| [`lint_cargo.py`](./lint/lint_cargo.py) | Deny dependencies per [`deny.toml`](../.cargo/deny.toml), check/format TOML files against [`taplo.toml`](./taplo.toml) | `check` , `apply`, `apply-all` | `cargo-deny` (deny dependencies), `taplo` (TOML formatting) |
| [`lint_codeql.py`](./lint/lint_codeql.py) | Query Rust sources against [`maint/codeql/rust/*.ql`](./codeql/rust) | `check`, `apply`, `apply-all`, `run`, `run-all` | `codeql`, `rustc` |
| [`lint_javascript.py`](./lint/lint_javascript.py) | Lint Javascript sources against [`eslint.config.mjs`](js/eslint.config.mjs) | *None* | `npx` (part of Node.js), `eslint` (auto-retrieved by script) |
| [`lint_just.py`](./lint/lint_just.py) | Lint the root `Justfile` and every module against `just --fmt` | `check`, `apply`, `apply-all` | `just`, `git` |
| [`lint_markdown.py`](./lint/lint_markdown.py) | Lint Markdown [documentation](../docs/dev/about_docs.md) | *None* | `pymarkdownlnt` |
| [`lint_nix.py`](./lint/lint_nix.py) | Lint Nix sources against `nixfmt`'s RFC 166 style | `check`, `apply`, `apply-all` | `nixfmt`, `git` |
| [`lint_python.py`](./lint/lint_python.py) | Lint Python sources against `[tool.ruff]` options in [`pyproject.toml`](../pyproject.toml) | *None* | `ruff` |
| [`lint_rust.py`](./lint/lint_rust.py) | Lint Rust sources against [`rustfmt.toml`](../rustfmt.toml) | *None* | `cargo`, `rustfmt` |
| [`lint_semgrep.py`](./lint/lint_semgrep.py) | Lint source code against [`maint/semgrep`](./semgrep/rust) definitions | *None* | `semgrep` |
| [`lint_symlinks.py`](./lint/lint_symlinks.py) | Lint symbolic links | *None* | `git` |

## Generating lockfiles

> [!NOTE]
> Lockfiles should only be generated with `uv`. Using other Python package managers like `poetry` are unsupported.

If [`pyproject.toml`](../pyproject.toml) has been modified, it is recommended to regenerate the lockfile to ensure
dependencies are pinned.

```bash
# After modifying pyproject.toml
uv lock
```
