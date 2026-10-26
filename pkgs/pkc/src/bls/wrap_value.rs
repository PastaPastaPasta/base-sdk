//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The object Core's BLS wrapper holds: its validity and its element.

use super::scheme_ctx::BlsSchemeKind;
use super::wrap_codec::BlsWire;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use dash_types::Numeric;
use hex_conservative::DisplayHex;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};

/// A BLS object as `CBLSWrapper` holds one: its `fValid` flag and its
/// element `impl`, kept apart as Core keeps them.
///
/// An invalid object serializes as zeros in both schemes, whatever its
/// element. Decoding leaves it Core's default element; an operation that
/// fails in place can keep the element it held. A valid object serializes
/// its element in either scheme.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsValue<K: BlsWire<N>, const N: usize> {
  valid: bool,
  element: Element<K, N>,
}

/// An object's element. A secret key's bytes are redacted, kept out of
/// hashes, compared in constant time and wiped on drop.
#[cfg_attr(feature = "codec", derive(Unencodable))]
struct Element<K: BlsWire<N>, const N: usize> {
  /// Core's basic-scheme serialization, from which the legacy one follows.
  basic: [u8; N],
  point: K::Point,
  /// The coord tag, or relic's coordinates for an engine result.
  repr: K::Repr,
}

impl<K: BlsWire<N>, const N: usize> BlsValue<K, N> {
  /// Core's default object: invalid, holding the default element.
  pub fn invalid() -> Self {
    let (basic, point) = K::default_element();
    Self {
      valid: false,
      element: Element {
        basic,
        point,
        repr: K::Repr::default(),
      },
    }
  }

  fn valid(basic: [u8; N], point: K::Point) -> Self {
    Self::with_element(basic, point, K::Repr::default())
  }

  /// A valid object holding an element as an arithmetic result gives it.
  pub(crate) fn with_element(basic: [u8; N], point: K::Point, repr: K::Repr) -> Self {
    Self {
      valid: true,
      element: Element { basic, point, repr },
    }
  }

  /// The element whatever the validity, Core's `impl`, as it is held: its
  /// basic serialization, point and representation.
  pub(crate) fn parts(&self) -> (&[u8; N], &K::Point, &K::Repr) {
    (&self.element.basic, &self.element.point, &self.element.repr)
  }

  /// Decodes bytes that are canonical under `scheme`, the check Core's lazy
  /// wrapper applies. That is `SetBytes`, then the round trip, with no
  /// fallback.
  ///
  /// Returns `None` unless the bytes decode to a valid object that
  /// re-serializes under `scheme` to the same bytes.
  pub fn from_canonical(bytes: &[u8; N], scheme: BlsSchemeKind) -> Option<Self> {
    K::decode_canonical(bytes, scheme).map(|(basic, point)| Self::valid(basic, point))
  }

  /// Decodes as Core's `SetBytes(bytes, false)` does, under the basic scheme
  /// with no round trip and no fallback. Core reads governance and CoinJoin
  /// signatures this way.
  ///
  /// Bytes of the wrong length, all-zero bytes and bytes that do not decode
  /// give the invalid object. Otherwise this is canonical basic decoding,
  /// unless `bytes` hold a G2 subgroup point with `y` in `Fp` and the sign
  /// bit set, of which none is known; relic serializes it with the sign bit
  /// clear. For secret keys the flag is Core's `modOrder`, also false.
  pub fn from_set_bytes_basic(bytes: &[u8]) -> Self {
    let decoded = <&[u8; N]>::try_from(bytes).ok().and_then(K::decode_set_basic);
    decoded.map_or_else(Self::invalid, |(basic, point)| Self::valid(basic, point))
  }

  /// Whether the object is valid, Core's `IsValid`.
  pub fn is_valid(&self) -> bool {
    self.valid
  }

  /// Runs a legacy-decoded element's subgroup test once, where the object
  /// is kept: an element in the subgroup is no longer tested by each
  /// verification under the legacy flag, which Core runs without that test.
  /// Equality, hashing and every verdict are unchanged.
  pub fn resolve(&mut self) {
    K::resolve(&mut self.element.point);
  }

  /// Marks the object invalid and keeps its element, as Core's in-place
  /// operations (`SecretKeyShare`, `PublicKeyShare`, `Recover`,
  /// `DHKeyExchange`) do when they return `false`.
  pub fn invalidate(&mut self) {
    self.valid = false;
  }

  /// The element of a valid object.
  pub fn point(&self) -> Option<&K::Point> {
    self.valid.then_some(&self.element.point)
  }

  /// The element whatever the validity, Core's `impl`: its serialization
  /// under `scheme` and its point.
  pub(crate) fn element(&self, scheme: BlsSchemeKind) -> ([u8; N], &K::Point) {
    (K::encode(&self.element.basic, scheme), &self.element.point)
  }

  /// Serializes under `scheme`, Core's `ToBytes`; zeros when invalid. For a
  /// secret key the copy is the caller's to wipe.
  pub fn to_bytes(&self, scheme: BlsSchemeKind) -> [u8; N] {
    if self.valid {
      K::encode(&self.element.basic, scheme)
    } else {
      [0u8; N]
    }
  }

  /// `GetHash()` under `scheme`: SHA-256d of [`Self::to_bytes`], zeros for
  /// an invalid object (`bls.h:141-147`). Core caches the hash with the
  /// flag of its first call and keeps it across a flag change; a caller that
  /// needs that keeps the hash itself.
  pub fn serialize_hash(&self, scheme: BlsSchemeKind) -> Hash256 {
    let mut bytes = self.to_bytes(scheme);
    let hash = Hash256::from_lendian(Sha256d::hash(&bytes).to_byte_array());
    bytes.zeroize();
    hash
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for BlsValue<K, N> {
  fn clone(&self) -> Self {
    Self {
      valid: self.valid,
      element: self.element.clone(),
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for BlsValue<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if self.valid {
      write!(f, "BlsValue({:?})", self.element)
    } else if self.element == Self::invalid().element {
      f.write_str("BlsValue(invalid)")
    } else {
      write!(f, "BlsValue(invalid, {:?})", self.element)
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for BlsValue<K, N> {}

/// Secret keys hash only their validity, so they make poor hash keys.
impl<K: BlsWire<N>, const N: usize> Hash for BlsValue<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.valid.hash(state);
    self.element.hash(state);
  }
}

/// The same validity, serialized bytes and held point, while the hash
/// covers the validity and the bytes (the validity alone for secret keys).
/// That is finer than Core's container
/// key, as `operator<` orders by `GetHash()` of the serialization alone
/// (`bls.h:85-87,141-146`); the two agree whenever the bytes determine the
/// point. On decoded values it is Core's `operator==`; on arithmetic results
/// that operator does not normalize and is not transitive, so it is
/// `core_eq` (BS11a-3 D25). To dedupe as Core's `std::set` and `std::map`
/// do, key by `to_bytes(scheme)`.
impl<K: BlsWire<N>, const N: usize> PartialEq for BlsValue<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.valid == other.valid && self.element == other.element
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for Element<K, N> {
  fn clone(&self) -> Self {
    Self {
      basic: self.basic,
      point: self.point.clone(),
      repr: self.repr.clone(),
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for Element<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if K::SECRET {
      f.write_str("[redacted]")
    } else {
      write!(f, "{}", self.basic.as_hex())
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Drop for Element<K, N> {
  fn drop(&mut self) {
    if K::SECRET {
      self.basic.zeroize();
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for Element<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for Element<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    if !K::SECRET {
      self.basic.hash(state);
    }
  }
}

/// Elements are compared by what Core serializes, and the representation is
/// ignored. A canonical encoding determines its element, but
/// [`BlsValue::from_set_bytes_basic`] would give a G2 subgroup point with `y`
/// in `Fp` and its negation one serialization, so points are compared too.
/// Whether a legacy point's subgroup test has run is not compared.
impl<K: BlsWire<N>, const N: usize> PartialEq for Element<K, N> {
  fn eq(&self, other: &Self) -> bool {
    bool::from(self.basic.ct_eq(&other.basic)) && self.point == other.point
  }
}
