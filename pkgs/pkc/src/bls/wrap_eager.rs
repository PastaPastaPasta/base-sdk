//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Eagerly decoded BLS fields, Core's `CBLSWrapper::Unserialize`.

use super::group::{G1, G2};
use super::scalar::Fr;
use super::scheme_ctx::{BlsSchemeKind, BlsSchemeSource};
use super::wrap_codec::{is_zero, BlsWire};
use super::wrap_value::BlsValue;
use super::{BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};

/// Core's "malleable BLS object" error; the bytes are canonical in neither
/// scheme.
///
/// It fails the decode of the enclosing object. For a special transaction's
/// payload, the rules then report Core's `bad-*-payload`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlsDecodeError;

impl fmt::Display for BlsDecodeError {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.write_str("malleable BLS object")
  }
}

#[cfg(feature = "std")]
impl std::error::Error for BlsDecodeError {}

/// A BLS field decoded together with the object that carries it.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsEager<K: BlsWire<N>, const N: usize> {
  value: BlsValue<K, N>,
  scheme: BlsSchemeKind,
}

/// An eagerly decoded public key.
pub type BlsEagerPk = BlsEager<G1, BLS_PK_LEN>;
/// An eagerly decoded signature.
pub type BlsEagerSig = BlsEager<G2, BLS_SIG_LEN>;
/// An eagerly decoded secret key.
pub type BlsEagerSk = BlsEager<Fr, BLS_SK_LEN>;

impl<K: BlsWire<N>, const N: usize> BlsEager<K, N> {
  /// Decodes as Core's `Unserialize` does under the scheme `source` picks.
  ///
  /// All-zero bytes are the invalid object. Bytes canonical in the scheme
  /// decode to their element. Bytes canonical only in the other scheme give
  /// the invalid object, which serializes as zeros.
  ///
  /// # Errors
  ///
  /// Returns [`BlsDecodeError`] when the bytes are canonical in neither
  /// scheme, the identity encoding included.
  pub fn decode(bytes: &[u8; N], source: BlsSchemeSource) -> Result<Self, BlsDecodeError> {
    let scheme = source.kind();
    let value = if is_zero(bytes) {
      BlsValue::invalid()
    } else if let Some(value) = BlsValue::from_canonical(bytes, scheme) {
      value
    } else if K::is_canonical(bytes, scheme.opposite()) {
      BlsValue::invalid()
    } else {
      return Err(BlsDecodeError);
    };
    Ok(Self { value, scheme })
  }

  /// Wraps a value, recording the scheme it belongs to.
  pub fn new(value: BlsValue<K, N>, scheme: BlsSchemeKind) -> Self {
    Self { value, scheme }
  }

  /// The decoded object.
  pub fn value(&self) -> &BlsValue<K, N> {
    &self.value
  }

  /// Consumes the field, returning the decoded object.
  pub fn into_value(self) -> BlsValue<K, N> {
    self.value
  }

  /// The scheme the field was decoded under.
  pub fn scheme(&self) -> BlsSchemeKind {
    self.scheme
  }

  /// Whether the object is valid, Core's `IsValid`.
  pub fn is_valid(&self) -> bool {
    self.value.is_valid()
  }

  /// Serializes under `scheme`, Core's `Serialize(s, scheme)`; zeros when
  /// invalid.
  ///
  /// Core serializes under the version's scheme or under its global flag at
  /// the time, which can differ from the decode scheme.
  pub fn to_bytes(&self, scheme: BlsSchemeKind) -> [u8; N] {
    self.value.to_bytes(scheme)
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for BlsEager<K, N> {
  fn clone(&self) -> Self {
    Self {
      value: self.value.clone(),
      scheme: self.scheme,
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for BlsEager<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlsEager")
      .field("value", &self.value)
      .field("scheme", &self.scheme)
      .finish()
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for BlsEager<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for BlsEager<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.value.hash(state);
  }
}

/// Core's `operator==` compares objects; the decode scheme is not part of one.
impl<K: BlsWire<N>, const N: usize> PartialEq for BlsEager<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.value == other.value
  }
}
