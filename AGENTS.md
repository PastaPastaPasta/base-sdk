# Development Guide

## Coding style

The full guide is at [`docs/dev/guide_rust.md`](./docs/dev/guide_rust.md). Key points:

- **Formatting**: 2-space indentation, LF line endings, no trailing whitespace, single newline at end of file. Max line
  width 120, comment width 80. Enforced by `rustfmt.toml`.
- **Naming**: `UpperCamelCase` for types/traits/enum variants, `snake_case` for functions/variables/modules,
  `SCREAMING_SNAKE_CASE` for constants. Acronyms as words (`TxId` not `TXID`). Getters omit `get_` prefix.
- **Type safety**: newtypes over primitives when semantics differ, enums over booleans, make invalid states
  unrepresentable. Derive `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash` eagerly.
- **Error handling**: never `.unwrap()` or `.expect()` in library code. Propagate with `?`. Domain error enums implement
  `Display`. Lowercase messages without trailing punctuation. Use `#[expect]` over `#[allow]`.
- **Ownership**: prefer borrowing over cloning, accept `&str` over `&String`, `&[T]` over `&Vec<T>`. Let the caller
  decide when to clone.
- **Conversions**: `as_` (free, borrow), `to_` (allocates), `into_` (consumes). Implement `From`/`TryFrom`, never `Into`
  directly.
- **Comments**:
  - Inline comments max 80 chars, 3 lines.
  - Rustdoc summary max 3 lines, don't restate the signature.
  - Document `# Errors` for `Result`-returning functions.
  - Comments are brief and either directly relevant to the reader or actionable.
  - Avoid colons; prefer semicolons, periods and commas.
  - Split run-on sentences and multi-clause sentences to prevent reading fatigue, balance against sentence
    fragmentation.
  - No vague references (`the other`, `that thing`); name the item.
  - No exposition, history, or conversational tone.
- **Code segmentation**: organise code through modules (in-file or separate files) and naming prefixes. Never use
  decorative separator comments (`// ----`, `// ====`, `// -- Section --`). Latin-1/ISO 8859-1 characters in source
  files only; no Unicode dashes, arrows, box drawing, or other decoration in comments or identifiers.
- **Security**: never log secrets, custom `Debug` for sensitive types, use `subtle` for constant-time comparison of
  secrets, `zeroize` after use.

## Crate standards

### Environment

- `no_std` + `alloc` is mandatory for all crates. Every crate uses `#![no_std]` with `extern crate alloc`.
- `std` is an optional feature that downstream consumers enable when they need stdlib I/O, `Error` impls, etc.
- No networking code in any crate. The SDK provides encoding, decoding, and data types only.

### Feature flags

Every crate must follow this feature layout:

```toml
[features]
default = []
std = [...]
full = ["std"]            # add "serde" here if the crate implements Serialize/Deserialize, do not include "portable"
portable = [...]          # only if the crate or a dependency defines platform acceleration
serde = ["dep:serde"]     # only if the crate has serde impls
```

### Module conventions

Any shim code that mediates between `alloc` and `std` (e.g. `pub(crate) use alloc::vec::Vec;`) belongs in
`crate::prelude`.

### File layout

Every `.rs` file follows this order:

```rust
//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! One-line module description.

use crate::some_internal_module;

use some_external_crate;

// ... code ...
```

1. Copyright header (5-line block, more if additional attribution needed)
2. Blank line
3. Module doc (`//!`): one line, plus an optional 3-line paragraph
   for exceptional cases
4. Blank line
5. Internal imports (`use crate::...`, `use super::...`)
6. Blank line
7. External imports (`use some_crate::...`)
8. Blank line
9. Code

### Test and bench tooling

- **Tests**: use `rstest` for parametrized and fixture-based tests.
- **Benchmarks**: use `divan` as the benchmark harness.
- **Corpus data**: must be JSON5 (`.json5` files in `corpus/`). JSON5 allows comments for annotating test vectors.

### Directory layout

```text
pkgs/<name>/
  bench/
  corpus/
  src/
  tests/
  Cargo.toml
```

`Cargo.toml` must set:

```toml
[package]
name = "dash-<name>"

[lints]
workspace = true
```

### Internal dependencies

Crates within this repo must specify `path` and `version`:

```toml
dash-num = { version = "0.0.0", path = "../num" }
```

## Verification

All changes must pass before merge.

```sh
just test lint
```
