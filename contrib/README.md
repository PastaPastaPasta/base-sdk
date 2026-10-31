`base-sdk` uses a family of tools and scripts to maintain correctness and code quality. These scripts are written in
Python 3.x and thus, assume a host capable of running Python. For guidance on installing Python on your host, visit
<https://www.python.org/downloads/>

<!-- [start:setup] -->

## Preparing the virtual environment

To avoid conflicting with your existing environment or with Python-based native packages managed by your host, it is
recommended to create a fresh virtual environment.

> [!NOTE]
> This guide presumes [`uv`](https://github.com/astral-sh/uv) has already been installed on your host. Please refer to
> your program of choice's documentation if using a different manager.

```bash
# Create .venv and install the versions uv.lock pins
uv sync --locked --extra dev

# Enter venv
source .venv/bin/activate
```

> [!WARNING]
> The minimum supported version is Python 3.11, support for prior versions are not expected. If you are running a more
> recent version of Python and are experiencing problems, please
> [file an issue](https://github.com/dashpay/base-sdk/issues/new).

## Installing dependencies

[`pyproject.toml`](../pyproject.toml) supplies most but not all dependencies needed to run the lint suite, the following
packages need to be additionally sourced.

* [cargo-deny](https://github.com/EmbarkStudios/cargo-deny)
* [cargo-hack](https://github.com/taiki-e/cargo-hack)
* [cargo-mutants](https://mutants.rs)
* [cargo-nextest](https://github.com/nextest-rs/nextest)
* [CodeQL 2.27 or higher](https://github.com/github/codeql-cli-binaries/releases)
* [Git](https://git-scm.com/install/)
* [just](https://just.systems) (task runner, see [`Justfile`](../Justfile)) and optionally, its
  language server, [`just-lsp`](https://www.just-lsp.systems)
* [Node.js 24 or higher](https://nodejs.org/en/download) (current LTS,
  [source](https://nodejs.org/en/blog/release/v24.11.0))

### macOS (with [Homebrew](https://brew.sh/))

> [!NOTE]
> Versioned formulae like `node@24` are considered "keg-only", which may require additional steps in order to be
> discoverable in `PATH`, see guidance from Homebrew
> ([source](https://docs.brew.sh/FAQ#what-does-keg-only-mean)).

```bash
brew install cargo-deny cargo-hack cargo-mutants cargo-nextest codeql git just just-lsp node@24
```

### Linux/WSL

See manual installation steps for CodeQL from GitHub
([source](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)),
you may need to update your shell to add your installation path to `PATH` so that `codeql` can be discovered by the
lint script.

Neither CodeQL nor taplo are available in official Debian or Fedora repositories and must be sourced per vendor
guidance. `cargo-hack`, `cargo-mutants`, `cargo-nextest` and `just-lsp` are likewise best installed as Rust binary
crates.

```bash
cargo install --locked cargo-hack cargo-mutants cargo-nextest just-lsp
```

#### Installing `taplo`

> [!WARNING]
> `.[dev]` doesn't provide `taplo`, needed to run `lint_cargo` on Arm64 Linux. This is due to a release limitation at
> PyPi ([source](https://pypi.org/project/taplo/0.9.3/#files)). The following guidance is not necessary on AMD64 Linux
> or macOS.

An alternative to procuring releases from the maintainers ([source](https://github.com/tamasfe/taplo/releases)) is to
install it as a Rust binary crate.

```bash
cargo install --locked taplo-cli
```

#### Debian

```bash
# Required because Debian trixie ships Node 20.x, deprecated in April 2026
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install git just nodejs -y

# `cargo-deny` is currently unavailable on Debian (https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=951368)
cargo install --locked cargo-deny
```

#### Fedora

```bash
sudo dnf install -y cargo-deny git just nodejs24
```

## Bazel

> [!NOTE]
> Bazel isn't installed directly. Instead, [Bazelisk](https://github.com/bazelbuild/bazelisk) is installed as `bazel`,
> which uses the version pinned by [`.bazelversion`](../.bazelversion). It is accompanied by
> [buildifier](https://github.com/bazelbuild/buildtools), used to lint Starlark (the DSL used by Bazel) files.

<!-- pyml disable-next-line no-duplicate-heading -->
### macOS (with [Homebrew](https://brew.sh/))

> [!WARNING]
> `bazelisk` conflicts with the `bazel` formula. If the latter has been installed, it must be uninstalled first.

```bash
brew install bazelisk buildifier
```

<!-- pyml disable-next-line no-duplicate-heading -->
### Linux/WSL

Neither Bazelisk nor buildifier are available in official Debian or Fedora repositories. Both are published to the npm
registry and can be installed with the `npm` CLI tool (a part of Node.js, an existing dependency).

```bash
npm install -g @bazel/bazelisk @bazel/buildifier
```

<!-- [end:setup] -->

<!-- [start:bisect] -->

## Verifying bisectability

As a general rule of thumb, each commit must individually compile and pass linters. To help with this, we have a helper
script, [`git_filter.py`](./git_filter.py) that creates a temporary worktree and executes supplied commands for each
commit in a specified range so the worktree isn't blocked by the validation run.

```bash
just comb
```

<!-- [end:bisect] -->
