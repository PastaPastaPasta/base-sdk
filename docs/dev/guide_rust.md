# Style Guide (Rust)

## Formatting

- Use 2-space indentation, LF line endings
- Files end with a single newline
- No trailing whitespace

<details>

<summary>Example code:</summary>

```rust
fn decode_block(raw: &[u8]) -> Result<Block, DecodeError> {
  let header = decode_header(raw)?;
  let txs = decode_transactions(&raw[80..])?;
  Ok(Block { header, txs })
}
```

</details>

## Naming

| Form                   | Used for                                            |
| ---------------------- | --------------------------------------------------- |
| `UpperCamelCase`       | Types, traits, enum variants, type parameters       |
| `snake_case`           | Functions, methods, variables, modules, crate names |
| `SCREAMING_SNAKE_CASE` | Constants and statics                               |
| `'lowercase`           | Lifetimes (`'a`, `'de`, `'src`)                     |

- Treat acronyms as whole words: write `TxId`, not `TXID`; `BlsPublicKey`, not `BLSPublicKey`
- Getters omit the `get_` prefix because the field name alone is unambiguous; a mutable getter appends `_mut`
- Primary constructors are named `new`; alternatives use descriptive names or `with_` suffixes (`with_capacity`)
- Conversion constructors use `from_` followed by the source type: `Hash256::from_bytes`
- Error type names follow verb-object-error word order so they sort and read predictably: `DecodeError`, not `ErrorDecode`

<details>

<summary>Example code:</summary>

```rust
const MAX_BLOCK_SIZE: usize = 2_000_000;

struct ChainTip {
  height: u64,
  hash: BlockHash,
}

impl ChainTip {
  // Getter omits the get_ prefix; the field name alone
  // is unambiguous.
  fn height(&self) -> u64 {
    self.height
  }

  // Mutable getter appends _mut.
  fn hash_mut(&mut self) -> &mut BlockHash {
    &mut self.hash
  }
}
```

</details>

## Type Safety

The type system is the first line of defence. A constraint expressed as a type is checked at compile time and
costs nothing at runtime.

> [!TIP]
> Prefer `#[derive]` for standard trait implementations. A manual implementation is warranted only when the
> derived behaviour would be incorrect or when redaction is needed.

- Wrap primitive types in newtypes when two values of the same underlying type carry different semantics; this prevents
  accidental transposition of arguments
- Prefer enums over booleans for function parameters because `Script::classify(P2pkh)` communicates intent where
  `Script::classify(true)` does not
- Make invalid states unrepresentable; if a combination of fields is logically impossible, restructure the type so the
  compiler rejects it
- Derive common traits eagerly on public types: `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`; the orphan rule prevents
  downstream crates from adding them later
- All public types implement `Debug` because diagnostic output and test assertions depend on it; for types holding
  sensitive data, provide a custom implementation that redacts the secret

<details>

<summary>Example code:</summary>

```rust
// Good: newtypes prevent mixing up hash types at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TxHash(Hash256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct BlockHash(Hash256);

fn lookup_tx(
  block: &BlockHash,
  tx: &TxHash,
) -> Option<Transaction> {
  // The compiler rejects lookup_tx(tx, block); the types differ.
}
```

```rust
// Good: custom Debug redacts the secret from panic messages.
struct SecretKey([u8; 32]);

impl core::fmt::Debug for SecretKey {
  fn fmt(
    &self,
    f: &mut core::fmt::Formatter<'_>,
  ) -> core::fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
```

</details>

## Error Handling

> [!IMPORTANT]
> Never call `.unwrap()` or `.expect()` on `Result` or `Option` in library code. A panic converts a
> recoverable failure into process-level failure; depending on the panic strategy, the code may unwind or
> abort, but either outcome is unacceptable for routine error handling.
>
> Propagate errors with `?` or handle them explicitly with `match`. Both `clippy::unwrap_used` and
> `clippy::expect_used` are denied at the workspace level.

- Define domain-specific error enums and derive `thiserror::Error`, which generates `Display` from `#[error]`
  attributes
- Error messages are lowercase and carry no trailing punctuation; they may be embedded in larger messages by
  callers, so capitalization and periods would read awkwardly in the middle of a sentence
- Keep `?` chains short; if a function contains more than a few `?` calls on unrelated operations, each
  operation likely belongs in its own function
- Use `#[expect]` instead of `#[allow]` when suppressing a lint; `expect` causes a warning if the suppression
  becomes unnecessary, preventing stale overrides from accumulating silently
- The `.todo()`, `.unimplemented()`, and `.unreachable()` family of panicking stubs are not permitted; if a
  branch is genuinely unreachable, restructure the types so the compiler can prove it

<details>

<summary>Example code:</summary>

```rust
/// Errors produced by BLS operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
  /// secret key bytes are not a valid scalar
  #[error("invalid secret key bytes")]
  InvalidSecretKey,
  /// public key bytes are not a valid G1 point
  #[error("invalid public key bytes")]
  InvalidPublicKey,
  /// signature verification failed
  #[error("signature verification failed")]
  VerifyFailed,
}
```

```rust
// Good: propagation with ?; the caller decides how to handle the error.
fn verify_header(
  raw: &[u8],
) -> Result<BlockHeader, DecodeError> {
  if raw.len() < 80 {
    return Err(DecodeError::Eof {
      needed: 80,
      remaining: raw.len(),
    });
  }
  let header = decode_header(raw)?;
  validate_pow(&header)?;
  Ok(header)
}
```

```rust
// Bad: unwrap turns a recoverable error into process termination.
fn verify_header(raw: &[u8]) -> BlockHeader {
  let header = decode_header(raw).unwrap();
  validate_pow(&header).unwrap();
  header
}
```

</details>

## Ownership and Borrowing

Rust's ownership model eliminates data races and use-after-free at compile time. Working with it, rather than
around it, produces code that is both safe and efficient.

- Prefer borrowing over cloning; cloning allocates and copies, and signals to readers that the caller needs
  an independent copy
- Accept the most general reference that satisfies the function: `&str` rather than `&String`, `&[T]` rather
  than `&Vec<T>`; this lets callers pass any type that dereferences to the expected slice
- Return owned values when the caller needs ownership; returning a reference to a local is a compile error,
  and this is intentional
- Let the caller decide when to clone; a function that silently clones its input adds hidden cost and
  prevents the caller from choosing a cheaper alternative

<details>

<summary>Example code:</summary>

```rust
// Good: accepts &[u8]; works with Vec<u8>, &[u8], arrays, etc.
fn hash_payload(data: &[u8]) -> Hash256 {
  // ...
}

// Bad: forces the caller to own a Vec even when a borrow would suffice.
fn hash_payload(data: &Vec<u8>) -> Hash256 {
  // ...
}
```

</details>

## Conversions

Consistent conversion names tell the reader the cost and ownership semantics of an operation at a glance.

| Prefix  | Cost                  | Ownership      | Example                   |
| ------- | --------------------- | -------------- | ------------------------- |
| `as_`   | Free                  | `&T` to `&U`   | `KeyId::as_bytes()`       |
| `to_`   | Allocates or computes | Borrows input  | `Hash256::to_bytes()`     |
| `into_` | Variable              | Consumes input | `String::into_bytes()`    |

- Implement `From<T>` for infallible conversions; the blanket impl provides `Into<T>` automatically, so we
  never implement `Into` directly
- Implement `TryFrom<T>` for conversions that can fail; the associated error type documents what can go wrong
- Implement `AsRef<T>` for cheap reference-to-reference conversions

<details>

<summary>Example code:</summary>

```rust
struct BlockHash([u8; 32]);

// Good: From for an infallible conversion.
impl From<[u8; 32]> for BlockHash {
  fn from(bytes: [u8; 32]) -> Self {
    Self(bytes)
  }
}

// Good: TryFrom for a fallible conversion; the error type documents failure.
impl TryFrom<&[u8]> for BlockHash {
  type Error = InvalidHashLength;

  fn try_from(
    slice: &[u8],
  ) -> Result<Self, Self::Error> {
    let arr: [u8; 32] = slice
      .try_into()
      .map_err(|_| InvalidHashLength(slice.len()))?;
    Ok(Self(arr))
  }
}

// Good: as_ prefix signals a free borrow with no allocation.
impl BlockHash {
  fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }
}
```

</details>

## Traits and Implementations

- Derive standard traits eagerly; the orphan rule prevents downstream crates from adding them, so we provide
  everything applicable up front
- Place `Serialize` and `Deserialize` behind an optional `serde` feature so crates that do not need
  serialization avoid the dependency; use `default-features = false` with `alloc` and `derive` features for
  `no_std` compatibility
- Sealed traits prevent downstream implementations; this allows adding methods in future versions without a breaking change

<details>

<summary>Example code:</summary>

```rust
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
  feature = "serde",
  derive(serde::Serialize, serde::Deserialize),
)]
pub struct OutPoint {
  pub txid: TxHash,
  pub vout: u32,
}
```

```rust
// Sealed trait: only types inside this crate may implement it.
pub trait Encoder: private::Sealed {
  fn encode(&self, buf: &mut alloc::vec::Vec<u8>);
}

mod private {
  pub trait Sealed {}
  impl Sealed for super::CompactEncoder {}
  impl Sealed for super::VerboseEncoder {}
}
```

</details>

## Generics

- Use `impl Trait` in argument position for simple, single-use bounds; use named type parameters when the
  same bound appears in multiple arguments or the return type
- Prefer static dispatch for performance-critical paths; use `dyn Trait` when the set of concrete types is
  open or when reducing binary size matters more than call overhead
- Do not add trait bounds to struct definitions unless the bound is required for the struct's own
  invariants; bounds on impls are sufficient and avoid constraining downstream code

<details>

<summary>Example code:</summary>

```rust
// Good: accepts any type that can be referenced as a byte slice.
fn compute_hash(data: impl AsRef<[u8]>) -> Hash256 {
  let bytes = data.as_ref();
  // ...
}
```

</details>

## Iterators

Iterator chains express data transformations declaratively. The compiler often optimises them into tight loops
with no intermediate allocations.

- Implement `iter()`, `iter_mut()`, and `into_iter()` on collection types; the return types are named
  `Iter`, `IterMut`, and `IntoIter` respectively
- Implement `FromIterator` and `Extend` so the collection works with `.collect()` and `.extend()`
- Prefer `filter_map()` when filtering and mapping happen together; it expresses the intent in one place
- Avoid `.collect()` when the result is only iterated once; return `impl Iterator<Item = T>` instead to
  defer allocation
- Implement `size_hint()` on custom iterators so downstream consumers can pre-allocate accurately

<details>

<summary>Example code:</summary>

```rust
// Good: filter_map fuses the filter and map steps into a single pass.
fn spendable_outputs(
  txs: &[Transaction],
) -> impl Iterator<Item = &TxOut> {
  txs.iter().filter_map(|tx| {
    if !tx.is_coinbase() {
      Some(&tx.outputs[0])
    } else {
      None
    }
  })
}
```

</details>

## Code Comments

Comments explain intent and context that the code alone cannot convey. Restating what the code does adds
noise and drifts out of sync with the implementation.

### Inline Comments

- Line comments (`//`) must not exceed 80 characters wide and 3 lines tall
- An extremely complex algorithm may use two short paragraphs separated by a blank comment line
- Focus on _why_ a decision was made, not _what_ the code does

### Rustdoc Comments

- Documentation comments (`///`) must not exceed 80 characters wide
- The summary is at most 3 lines; do not restate the function name or signature in prose because the reader
  can see them directly above
- Document `# Errors` when the function returns `Result`, listing each error variant and its cause
- Document `# Panics` only when the function can panic, which should be rare
- Pad lines so right columns align evenly for visual consistency
- Use `?` in doc examples instead of `.unwrap()` so readers copy safe patterns

<details>

<summary>Example code:</summary>

```rust
/// Decode a compact-encoded block header from raw bytes, verifying the
/// proof-of-work target against the declared difficulty.
///
/// # Errors
///
/// Returns `Eof` when the slice holds fewer than 80 bytes, or `BadTarget` when
/// the header fails the proof-of-work threshold.
fn decode_header(
  raw: &[u8],
) -> Result<Header, DecodeError> {
  // We validate length before field access to prevent out-of-bounds reads when
  // the slice comes from malformed or adversarial input.
  if raw.len() < 80 {
    return Err(DecodeError::Eof {
      needed: 80,
      remaining: raw.len(),
    });
  }
  // ...
}
```

```rust
// Bad: restates the signature, wall of text.

/// This function is called decode_header. It takes a byte slice called raw and
/// returns a Result containing either a Header or a DecodeError. The raw
/// parameter is the bytes to decode. If decoding succeeds it returns Ok with
/// the header inside.
fn decode_header(
  raw: &[u8],
) -> Result<Header, DecodeError> {
  // ...
}
```

</details>

## Development Guidelines

### Input Validation

> [!CAUTION]
> Assume every value decoded from the wire is adversarial. Trust boundaries include: consensus-encoded
> messages, peer-supplied byte streams, and any externally-produced data fed into a decoder.

- **Validate early, fail loudly.** Check length, range, and structural invariants before the value reaches
  domain logic; return a clear error that tells the caller exactly what is wrong
- **Encode validation in types.** A newtype that can only be constructed through a validating constructor
  carries its proof of validity with it; downstream code never needs to re-check
- **Limit input size.** Set maximum sizes for payloads and maximum element counts for collections; unbounded
  input is an invitation for resource exhaustion
- **Reject non-minimal encodings.** CompactSize, VarInt, and similar variable-length encodings must use their
  shortest representation; accepting non-minimal forms creates consensus divergence

<details>

<summary>Example code:</summary>

```rust
use core::fmt;

/// 20-byte key hash that can only be constructed from a validating constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 20]);

#[derive(Debug)]
pub struct InvalidKeyIdLength(pub usize);

impl fmt::Display for InvalidKeyIdLength {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "expected 20 bytes, got {}", self.0)
  }
}

impl KeyId {
  pub fn from_slice(
    bytes: &[u8],
  ) -> Result<Self, InvalidKeyIdLength> {
    let arr: [u8; 20] = bytes
      .try_into()
      .map_err(|_| InvalidKeyIdLength(bytes.len()))?;
    Ok(Self(arr))
  }

  pub fn as_bytes(&self) -> &[u8; 20] {
    &self.0
  }
}
```

</details>

### Security

> [!NOTE]
> Audit dependencies regularly. A single compromised or unmaintained transitive dependency can undermine all
> other precautions in the codebase.

- **Never log secrets.** Private keys, key shares, and seed material must never appear in log output, debug
  strings, or error messages
- **Implement `Debug` to redact sensitive fields.** A custom `Debug` that prints a placeholder prevents
  accidental exposure through `{:?}` formatting in panics
- **Use constant-time comparison for secrets.** Timing side-channels in byte-by-byte comparison leak
  information about secret values; use a constant-time equality function from a vetted cryptographic library
- **Zero sensitive memory after use.** Stack and heap buffers that held secrets should be zeroised before
  deallocation to reduce the window of exposure; the `zeroize` crate provides a `Zeroize` trait and a
  `ZeroizeOnDrop` derive for this purpose
- **Prefer explicit failure over silent defaults.** A default value for a missing secret silently degrades to
  an insecure state; failing explicitly is always safer than falling back to a placeholder

<details>

<summary>Example code:</summary>

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; 32]);

// Custom Debug prevents the key from appearing in panic output.
impl core::fmt::Debug for SecretKey {
  fn fmt(
    &self,
    f: &mut core::fmt::Formatter<'_>,
  ) -> core::fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
```

</details>
