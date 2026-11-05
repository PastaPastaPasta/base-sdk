//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! A decoded BLS point, valid or invalid.

use super::byte_bags::{BLS_PK_LEN, BLS_SIG_LEN};
use super::error::BlsError;
use super::group::{G1, G2};
use super::public_ops::BlsPublicKey;
use super::scheme_ctx::BlsSchemeKind;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use super::wrap_codec::{BlsPoint, BlsWire};

use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::DisplayHex;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};

/// A decoded BLS point, a valid element or the invalid object.
///
/// The invalid object encodes as zeros under both schemes. A valid one keeps
/// its element and encodes under either scheme.
///
/// A [`BlsPublicKey<S>`] or [`BlsSignature<S>`] converts to a value, and a
/// value to them, through the encoding under `S`, which must be canonical
/// under `S`. A point off the curve or outside the subgroup converts in
/// neither direction.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsValue<K: BlsWire<N>, const N: usize> {
  valid: Option<Valid<K, N>>,
}

/// The contents of a valid object.
#[cfg_attr(feature = "codec", derive(Unencodable))]
struct Valid<K: BlsWire<N>, const N: usize> {
  /// The basic encoding, from which the legacy one follows.
  basic: [u8; N],
  point: K::Point,
}

impl<K: BlsWire<N>, const N: usize> BlsValue<K, N> {
  /// The invalid object.
  pub const fn invalid() -> Self {
    Self { valid: None }
  }

  /// Decodes bytes canonical under `scheme`, with no fallback to the other
  /// scheme.
  ///
  /// Returns `None` unless the bytes are not all zero and `scheme` reads them
  /// as an element other than the identity that encodes back to them.
  pub fn from_canonical(bytes: &[u8; N], scheme: BlsSchemeKind) -> Option<Self> {
    K::decode(bytes, scheme).map(|(basic, point)| Self {
      valid: Some(Valid { basic, point }),
    })
  }

  /// Whether the object is valid.
  pub fn is_valid(&self) -> bool {
    self.valid.is_some()
  }

  /// The point of a valid object.
  pub fn point(&self) -> Option<&K::Point> {
    self.valid.as_ref().map(|valid| &valid.point)
  }

  /// Encodes under `scheme`, zeros when invalid.
  pub fn to_bytes(&self, scheme: BlsSchemeKind) -> [u8; N] {
    match &self.valid {
      Some(valid) => K::encode(&valid.basic, scheme),
      None => [0u8; N],
    }
  }
}

type_cvrt!(for[S: BlsScheme] TryFrom<BlsValue<G1, BLS_PK_LEN>> for BlsPublicKey<S>, BlsError, |value| {
  value
    .point()
    .and_then(BlsPoint::usable)
    .ok_or(BlsError::InvalidPublicKey)
    .and_then(|_| Self::from_bytes(&value.to_bytes(S::KIND)))
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsPublicKey<S>> for BlsValue<G1, BLS_PK_LEN>, BlsError, |pk| {
  Self::from_canonical(&pk.to_bytes(), S::KIND)
    .filter(|value| value.point().and_then(BlsPoint::usable).is_some())
    .ok_or(BlsError::InvalidPublicKey)
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsValue<G2, BLS_SIG_LEN>> for BlsSignature<S>, BlsError, |value| {
  value
    .point()
    .and_then(BlsPoint::usable)
    .ok_or(BlsError::InvalidSignature)
    .and_then(|_| Self::from_bytes(&value.to_bytes(S::KIND)))
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsSignature<S>> for BlsValue<G2, BLS_SIG_LEN>, BlsError, |sig| {
  Self::from_canonical(&sig.to_bytes(), S::KIND)
    .filter(|value| value.point().and_then(BlsPoint::usable).is_some())
    .ok_or(BlsError::InvalidSignature)
});

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

/// The same validity and, for valid objects, the same encoding, which
/// determines the element.
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
    write!(f, "{}", self.basic.as_hex())
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for Valid<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for Valid<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.basic.hash(state);
  }
}

impl<K: BlsWire<N>, const N: usize> PartialEq for Valid<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.basic == other.basic
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{G1_OFF_SUBGROUP_CHIA, G2_OFF_SUBGROUP_CHIA, MSG_DEADBEEF, RSEED};
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey};

  use rstest::rstest;

  /// Two legacy `x`, 4 and 5, neither with a point in the subgroup, decode
  /// to objects that differ in the last byte only.
  #[test]
  fn values_differing_in_the_last_byte_differ() {
    let mut other = G1_OFF_SUBGROUP_CHIA;
    other[BLS_PK_LEN - 1] = 5;
    let a = BlsValue::<G1, BLS_PK_LEN>::from_canonical(&G1_OFF_SUBGROUP_CHIA, BlsSchemeKind::Legacy).unwrap();
    let b = BlsValue::<G1, BLS_PK_LEN>::from_canonical(&other, BlsSchemeKind::Legacy).unwrap();
    assert_ne!(a, b);
    assert_eq!(a, a.clone());
  }

  /// A key and a signature under each scheme convert to values and back, and
  /// the invalid object converts to neither.
  fn assert_bridges<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[1]).unwrap();
    let pk = sk.public_key();
    let sig = sk.sign_digest(&MSG_DEADBEEF);

    let value = BlsValue::<G1, BLS_PK_LEN>::try_from(&pk).unwrap();
    assert_eq!(value.to_bytes(S::KIND), pk.to_bytes());
    assert_eq!(BlsPublicKey::<S>::try_from(&value).unwrap(), pk);
    let value = BlsValue::<G2, BLS_SIG_LEN>::try_from(&sig).unwrap();
    assert_eq!(value.to_bytes(S::KIND), sig.to_bytes());
    assert_eq!(BlsSignature::<S>::try_from(&value).unwrap(), sig);

    assert!(BlsPublicKey::<S>::try_from(BlsValue::invalid()).is_err());
    assert!(BlsSignature::<S>::try_from(BlsValue::invalid()).is_err());
  }

  /// A legacy key and signature outside the subgroup, which the legacy
  /// scheme reads, convert in neither direction.
  #[test]
  fn exotic_values_do_not_convert() {
    let pk = BlsValue::<G1, BLS_PK_LEN>::from_canonical(&G1_OFF_SUBGROUP_CHIA, BlsSchemeKind::Legacy).unwrap();
    let sig = BlsValue::<G2, BLS_SIG_LEN>::from_canonical(&G2_OFF_SUBGROUP_CHIA, BlsSchemeKind::Legacy).unwrap();
    assert!(pk.point().is_some_and(|point| *point == BlsPoint::Exotic));
    assert!(sig.point().is_some_and(|point| *point == BlsPoint::Exotic));
    assert_eq!(BlsPublicKey::<BlsScChia>::try_from(pk), Err(BlsError::InvalidPublicKey));
    assert_eq!(
      BlsSignature::<BlsScChia>::try_from(sig),
      Err(BlsError::InvalidSignature)
    );

    let pk = BlsPublicKey::<BlsScChia>::from_bytes(&G1_OFF_SUBGROUP_CHIA).unwrap();
    let sig = BlsSignature::<BlsScChia>::from_bytes(&G2_OFF_SUBGROUP_CHIA).unwrap();
    assert_eq!(
      BlsValue::<G1, BLS_PK_LEN>::try_from(&pk).unwrap_err(),
      BlsError::InvalidPublicKey
    );
    assert_eq!(
      BlsValue::<G2, BLS_SIG_LEN>::try_from(&sig).unwrap_err(),
      BlsError::InvalidSignature
    );
  }

  #[rstest]
  #[case::chia(assert_bridges::<BlsScChia>)]
  #[case::ietf(assert_bridges::<BlsScIetf>)]
  fn values_convert_to_keys_and_signatures(#[case] assertion: fn()) {
    assertion();
  }
}
