//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS fields kept as bytes until first use.

use super::byte_bags::{BLS_PK_LEN, BLS_SIG_LEN};
use super::group::{G1, G2};
use super::scheme_ctx::BlsSchemeKind;
use super::wrap_codec::{is_zero, BlsWire};
use super::wrap_value::BlsValue;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use dash_types::Numeric;
use hex_conservative::DisplayHex;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};

/// A BLS point kept as bytes until first use, with the scheme it was read
/// under.
///
/// Reading never fails. Matching the reference implementation needs the
/// object to change on use, so the methods that change it take `&mut self`:
/// - a failed [`Self::get`] drops the bytes, after which the object encodes and
///   hashes as zeros;
/// - an object read from bytes, encoded under the other scheme before a
///   successful [`Self::get`], replaces the bytes with zeros.
///
/// [`Self::encoded`] and [`Self::encoded_as`] give the same bytes as
/// [`Self::to_bytes`] and [`Self::to_bytes_as`] without the change.
///
/// `==` compares the state: the current bytes, the scheme and the decoded
/// object. Comparing as the reference implementation does goes through
/// [`Self::eq_decode`].
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsLazy<K: BlsWire<N>, const N: usize> {
  /// The encoding under `scheme`, while current.
  bytes: Option<[u8; N]>,
  /// The scheme of `bytes`, and the one [`Self::to_bytes`] writes.
  scheme: BlsSchemeKind,
  /// The object, once decoded or set.
  value: Option<BlsValue<K, N>>,
}

/// A lazily decoded public key.
pub type BlsLazyPk = BlsLazy<G1, BLS_PK_LEN>;
/// A lazily decoded signature.
pub type BlsLazySig = BlsLazy<G2, BLS_SIG_LEN>;

impl<K: BlsWire<N>, const N: usize> BlsLazy<K, N> {
  /// The default object, which holds neither bytes nor an object, encodes as
  /// zeros and keeps `scheme`.
  pub const fn new(scheme: BlsSchemeKind) -> Self {
    Self {
      bytes: None,
      scheme,
      value: None,
    }
  }

  /// Keeps `bytes`, read under `scheme`. All-zero bytes give the default
  /// object.
  pub fn from_bytes(bytes: &[u8; N], scheme: BlsSchemeKind) -> Self {
    Self {
      bytes: (!is_zero(bytes)).then_some(*bytes),
      scheme,
      value: None,
    }
  }

  /// Holds `value`, to be written under `scheme`.
  pub fn from_value(value: BlsValue<K, N>, scheme: BlsSchemeKind) -> Self {
    Self {
      bytes: None,
      scheme,
      value: Some(value),
    }
  }

  /// Whether the object holds neither bytes nor an object.
  fn is_default(&self) -> bool {
    self.bytes.is_none() && self.value.is_none()
  }

  /// The object, decoded on first use with no fallback to the other scheme.
  ///
  /// The object is valid only when the bytes are canonical under the scheme.
  /// Otherwise the bytes are dropped, and the object is the default one from
  /// then on.
  pub fn get(&mut self) -> BlsValue<K, N> {
    if let Some(value) = &self.value {
      return value.clone();
    }
    let decoded = self
      .bytes
      .and_then(|bytes| BlsValue::from_canonical(&bytes, self.scheme));
    match decoded {
      Some(value) => self.value.insert(value).clone(),
      None => {
        self.bytes = None;
        BlsValue::invalid()
      }
    }
  }

  /// Encodes under the scheme, as [`Self::to_bytes_as`] does.
  pub fn to_bytes(&mut self) -> [u8; N] {
    self.to_bytes_as(self.scheme)
  }

  /// Encodes under `scheme`, as [`Self::encoded_as`] does.
  ///
  /// The object keeps the encoding as its bytes, and takes `scheme` as its
  /// scheme. The default object keeps its scheme.
  pub fn to_bytes_as(&mut self, scheme: BlsSchemeKind) -> [u8; N] {
    let bytes = self.encoded_as(scheme);
    if !self.is_default() {
      self.bytes = Some(bytes);
      self.scheme = scheme;
    }
    bytes
  }

  /// The bytes [`Self::to_bytes`] gives, without changing the object.
  pub fn encoded(&self) -> [u8; N] {
    self.encoded_as(self.scheme)
  }

  /// The bytes [`Self::to_bytes_as`] gives, without changing the object.
  ///
  /// Current bytes in `scheme` encode as themselves, and a decoded object as
  /// its encoding under `scheme`. Otherwise the object encodes as zeros: the
  /// default object, and an object read from bytes before a successful
  /// [`Self::get`], under the other scheme.
  pub fn encoded_as(&self, scheme: BlsSchemeKind) -> [u8; N] {
    match (&self.bytes, &self.value) {
      (Some(bytes), _) if self.scheme == scheme => *bytes,
      (_, Some(value)) => value.to_bytes(scheme),
      _ => [0u8; N],
    }
  }

  /// The double SHA-256 of the encoding under the scheme, which
  /// [`Self::to_bytes`] would give. Before any [`Self::get`] it covers the
  /// bytes the object was read from.
  pub fn serialize_hash(&mut self) -> Hash256 {
    let bytes = self.to_bytes();
    Hash256::from_lendian(Sha256d::hash(&bytes).to_byte_array())
  }

  /// The scheme the bytes are in, and the one [`Self::to_bytes`] writes.
  pub fn scheme(&self) -> BlsSchemeKind {
    self.scheme
  }

  /// Replaces the scheme and nothing else, so current bytes are then read
  /// under `scheme`.
  pub fn set_scheme(&mut self, scheme: BlsSchemeKind) {
    self.scheme = scheme;
  }

  /// Compares as matching the reference implementation needs, decoding both
  /// sides when neither their bytes nor their objects decide.
  ///
  /// Default objects equal each other only. Current bytes in the same scheme
  /// compare as bytes, and decoded objects as objects. Otherwise both sides
  /// are decoded with [`Self::get`], so a side whose bytes fail to decode
  /// becomes the default object.
  pub fn eq_decode(&mut self, other: &mut Self) -> bool {
    if self.is_default() || other.is_default() {
      return self.is_default() && other.is_default();
    }
    if let (Some(a), Some(b)) = (&self.bytes, &other.bytes) {
      if self.scheme == other.scheme {
        return a == b;
      }
    }
    if let (Some(a), Some(b)) = (&self.value, &other.value) {
      return a == b;
    }
    self.get() == other.get()
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for BlsLazy<K, N> {
  fn clone(&self) -> Self {
    Self {
      bytes: self.bytes,
      scheme: self.scheme,
      value: self.value.clone(),
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for BlsLazy<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlsLazy")
      .field("bytes", &self.bytes.as_ref().map(|bytes| bytes.as_hex()))
      .field("scheme", &self.scheme)
      .field("value", &self.value)
      .finish()
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for BlsLazy<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for BlsLazy<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.bytes.hash(state);
    self.scheme.hash(state);
    self.value.hash(state);
  }
}

/// The same state: the same current bytes, scheme and decoded object.
impl<K: BlsWire<N>, const N: usize> PartialEq for BlsLazy<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.bytes == other.bytes && self.scheme == other.scheme && self.value == other.value
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{G1_OFF_SUBGROUP_CHIA, G1_OFF_SUBGROUP_IETF};

  const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
  const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

  /// A failed `get` drops the bytes, so the object encodes as zeros and
  /// equals the default object.
  #[test]
  fn failed_get_drops_the_bytes() {
    let mut lazy = BlsLazyPk::from_bytes(&G1_OFF_SUBGROUP_CHIA, BASIC);
    assert_eq!(lazy.to_bytes(), G1_OFF_SUBGROUP_CHIA);
    assert!(!lazy.eq_decode(&mut BlsLazyPk::new(BASIC)));

    assert!(!lazy.get().is_valid());
    assert_eq!(lazy.to_bytes(), [0u8; BLS_PK_LEN]);
    assert_eq!(lazy, BlsLazyPk::new(BASIC));
  }

  /// Encoding under the other scheme before `get` drops the bytes; after a
  /// `get` it re-encodes the object.
  #[test]
  fn other_scheme_encoding_before_get_drops_the_bytes() {
    let mut unread = BlsLazyPk::from_bytes(&G1_OFF_SUBGROUP_CHIA, LEGACY);
    assert_eq!(unread.encoded_as(BASIC), [0u8; BLS_PK_LEN]);
    assert_eq!(unread.encoded(), G1_OFF_SUBGROUP_CHIA);
    assert_eq!(unread.to_bytes_as(BASIC), [0u8; BLS_PK_LEN]);
    assert_eq!(unread.scheme(), BASIC);
    assert!(!unread.get().is_valid());

    let mut read = BlsLazyPk::from_bytes(&G1_OFF_SUBGROUP_CHIA, LEGACY);
    assert!(read.get().is_valid());
    assert_eq!(read.to_bytes_as(BASIC), G1_OFF_SUBGROUP_IETF);
    assert_eq!(read.scheme(), BASIC);
    assert_eq!(read.to_bytes_as(LEGACY), G1_OFF_SUBGROUP_CHIA);
  }

  /// The default object encodes as zeros under the other scheme and keeps
  /// its scheme.
  #[test]
  fn default_object_keeps_its_scheme() {
    let mut lazy = BlsLazyPk::new(LEGACY);
    assert_eq!(lazy.to_bytes_as(BASIC), [0u8; BLS_PK_LEN]);
    assert_eq!(lazy.scheme(), LEGACY);
  }
}
