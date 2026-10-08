//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The object Core's BLS wrapper holds, a valid element or the invalid one.

use super::scheme_ctx::BlsSchemeKind;
use super::wrap_codec::BlsWire;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::DisplayHex;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};

/// A decoded BLS object as `CBLSWrapper` holds one, valid or invalid.
///
/// An invalid object serializes as zeros in both schemes. A valid one keeps
/// its element and serializes in either scheme.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsValue<K: BlsWire<N>, const N: usize> {
  valid: Option<Valid<K, N>>,
}

/// The contents of a valid object. A secret key's bytes are redacted, kept
/// out of hashes, compared in constant time and wiped on drop.
#[cfg_attr(feature = "codec", derive(Unencodable))]
struct Valid<K: BlsWire<N>, const N: usize> {
  /// Core's basic-scheme serialization, from which the legacy one follows.
  basic: [u8; N],
  point: K::Point,
}

impl<K: BlsWire<N>, const N: usize> BlsValue<K, N> {
  /// Core's default object, which is invalid.
  pub const fn invalid() -> Self {
    Self { valid: None }
  }

  /// Decodes bytes that are canonical under `scheme`, the check Core's lazy
  /// wrapper applies. That is `SetBytes`, then the round trip, with no
  /// fallback.
  ///
  /// Returns `None` unless the bytes decode to a valid object that
  /// re-serializes under `scheme` to the same bytes.
  pub fn from_canonical(bytes: &[u8; N], scheme: BlsSchemeKind) -> Option<Self> {
    K::decode_canonical(bytes, scheme).map(|(basic, point)| Self {
      valid: Some(Valid { basic, point }),
    })
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
    decoded.map_or_else(Self::invalid, |(basic, point)| Self {
      valid: Some(Valid { basic, point }),
    })
  }

  /// Whether the object is valid, Core's `IsValid`.
  pub fn is_valid(&self) -> bool {
    self.valid.is_some()
  }

  /// The element of a valid object.
  pub fn point(&self) -> Option<&K::Point> {
    self.valid.as_ref().map(|valid| &valid.point)
  }

  /// Serializes under `scheme`, Core's `ToBytes`; zeros when invalid. For a
  /// secret key the copy is the caller's to wipe.
  pub fn to_bytes(&self, scheme: BlsSchemeKind) -> [u8; N] {
    match &self.valid {
      Some(valid) => K::encode(&valid.basic, scheme),
      None => [0u8; N],
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for BlsValue<K, N> {
  fn clone(&self) -> Self {
    Self {
      valid: self.valid.clone(),
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for BlsValue<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match &self.valid {
      None => f.write_str("BlsValue(invalid)"),
      Some(valid) => write!(f, "BlsValue({valid:?})"),
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for BlsValue<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for BlsValue<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.valid.hash(state);
  }
}

/// Core's `operator==`, true for two invalid objects or the same element.
impl<K: BlsWire<N>, const N: usize> PartialEq for BlsValue<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.valid == other.valid
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for Valid<K, N> {
  fn clone(&self) -> Self {
    Self {
      basic: self.basic,
      point: self.point.clone(),
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for Valid<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if K::SECRET {
      f.write_str("[redacted]")
    } else {
      write!(f, "{}", self.basic.as_hex())
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Drop for Valid<K, N> {
  fn drop(&mut self) {
    if K::SECRET {
      self.basic.zeroize();
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for Valid<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for Valid<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    if !K::SECRET {
      self.basic.hash(state);
    }
  }
}

/// Core compares elements. A canonical encoding determines its element, but
/// [`BlsValue::from_set_bytes_basic`] would give a G2 subgroup point with `y`
/// in `Fp` and its negation one serialization, so points are compared too.
impl<K: BlsWire<N>, const N: usize> PartialEq for Valid<K, N> {
  fn eq(&self, other: &Self) -> bool {
    bool::from(self.basic.ct_eq(&other.basic)) && self.point == other.point
  }
}
