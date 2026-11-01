# Cross Compilation

> [!NOTE]
> This guide assumes access to a [development shell](./devshells.md). Attempting cross-compilation outside a devshell
> is not within the scope of this guide and is unsupported.

Cross-compilation is when the `host` and `target` of a binary diverge. Regular compilation has the goal of generating
immediately executable artifacts for the machine that is compiling (i.e. they share identical `host` and `target`),
while cross-compilation gains its value in being able to produce artifacts for consumption on other platforms without
procuring hardware or platform configurations for each desired target.

To achieve cross-compilation, the following are supplied:

* A thinned-down root filesystem (i.e. sysroot) with headers and libraries expected by `target`
* A compiler and linker that runs on the `host` but emits artifacts for the `target`
* The standard library required by `target`

We use an LLVM 20 toolchain (Clang as the compiler, LLD as the linker) for Rust packages that bind C/C++ codebases
through an FFI, with the standard library bundle supplied to `rustc` by cargo. `rustc` itself is first class native
cross-compiler.

> [!NOTE]
> Support for macOS and Windows cross-compilation is only available in the `#dev` devshell, it is omitted from the `#ci`
> devshell to reduce cache contention with our forge provider.

The following platforms are supported as `target`s **excluding the `host` platform**.

| Target                      | Object Format | Sysroot                     |
| --------------------------- | ------------- | --------------------------- |
| `aarch64-apple-darwin`      | Mach-O        | macOS SDK with libcxx       |
| `x86_64-apple-darwin`       | Mach-O        | macOS SDK with libcxx       |
| `aarch64-unknown-linux-gnu` | ELF           | glibc                       |
| `x86_64-unknown-linux-gnu`  | ELF           | glibc                       |
| `x86_64-pc-windows-gnu`     | PE32+         | MinGW-w64                   |
| `wasm32-unknown-unknown`    | Wasm          | *None*, no libc(++) support |

> [!NOTE]
> `<target>` spells the triple with underscores, as `cc-rs` reads it (e.g. `CC_aarch64_apple_darwin`), while
> `<TARGET>` spells the triple in upper case, as `cargo` reads it (e.g. `CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER`).

For each target, the following environment variables are defined

<!-- pyml disable-num-lines 6 table-column-style -->
| Environment Variable           | Description                             |
| ------------------------------ | --------------------------------------- |
| `CC_<target>`                  | The C compiler for `target`             |
| `CXX_<target>`                 | The C++ compiler for `target`           |
| `AR_<target>`                  | The archiver, `llvm-ar`                 |
| `CARGO_TARGET_<TARGET>_LINKER` | The linker for `target` used by `cargo` |

## Building (Rust)

> [!TIP]
> `--all-targets` is recommended when performing smoke tests to ensure the linker behaves as expected, since it
> brings test binaries into scope. `base-sdk` is primarily a collection of library crates, so without binaries to
> link, configuration failures may not surface.

```bash
# Building for ARM64 Linux (assuming an AMD64 host)
cargo build --workspace --all-targets --features full --target aarch64-unknown-linux-gnu
```
