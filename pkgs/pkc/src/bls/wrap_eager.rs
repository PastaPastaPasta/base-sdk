//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS points decoded with the object that carries them.

use super::byte_bags::{BLS_PK_LEN, BLS_SIG_LEN};
use super::error::BlsError;
use super::group::{G1, G2};
use super::scheme_ctx::BlsSchemeKind;
use super::wrap_codec::{is_zero, BlsWire};
use super::wrap_value::BlsValue;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};

/// A BLS point decoded with the object that carries it.
///
/// It encodes under the scheme the object is written under, which need not
/// be the one it was decoded under.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsEager<K: BlsWire<N>, const N: usize> {
  value: BlsValue<K, N>,
}

/// An eagerly decoded public key.
pub type BlsEagerPk = BlsEager<G1, BLS_PK_LEN>;
/// An eagerly decoded signature.
pub type BlsEagerSig = BlsEager<G2, BLS_SIG_LEN>;

impl<K: BlsWire<N>, const N: usize> BlsEager<K, N> {
  /// Decodes under `scheme`, as matching the reference implementation needs.
  ///
  /// All-zero bytes give the invalid object. Bytes canonical under the
  /// scheme give their element. Bytes canonical only under the other scheme
  /// give the invalid object, which encodes as zeros.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` or `InvalidSignature` when the bytes are
  /// canonical under neither scheme, the identity encoding included.
  pub fn decode(bytes: &[u8; N], scheme: BlsSchemeKind) -> Result<Self, BlsError> {
    let value = if is_zero(bytes) {
      BlsValue::invalid()
    } else if let Some(value) = BlsValue::from_canonical(bytes, scheme) {
      value
    } else if K::is_canonical(bytes, scheme.opposite()) {
      BlsValue::invalid()
    } else {
      return Err(K::INVALID);
    };
    Ok(Self { value })
  }

  /// Wraps a value.
  pub fn new(value: BlsValue<K, N>) -> Self {
    Self { value }
  }

  /// The decoded object.
  pub fn value(&self) -> &BlsValue<K, N> {
    &self.value
  }

  /// Whether the object is valid.
  pub fn is_valid(&self) -> bool {
    self.value.is_valid()
  }

  /// Encodes under `scheme`, zeros when invalid.
  pub fn to_bytes(&self, scheme: BlsSchemeKind) -> [u8; N] {
    self.value.to_bytes(scheme)
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for BlsEager<K, N> {
  fn clone(&self) -> Self {
    Self::new(self.value.clone())
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for BlsEager<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_tuple("BlsEager").field(&self.value).finish()
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for BlsEager<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for BlsEager<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.value.hash(state);
  }
}

/// The same object.
impl<K: BlsWire<N>, const N: usize> PartialEq for BlsEager<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.value == other.value
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{G1_OFF_SUBGROUP_CHIA, G1_OFF_SUBGROUP_IETF, G1_X_EQ_PRIME_CHIA};
  use crate::bls::BlsPoint;

  use rstest::rstest;

  const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
  const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

  /// Zeros under either scheme give the invalid object.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn zeros_are_invalid(#[case] scheme: BlsSchemeKind) {
    let decoded = BlsEagerPk::decode(&[0u8; BLS_PK_LEN], scheme);
    assert!(decoded.is_ok_and(|pk| !pk.is_valid() && pk.to_bytes(scheme) == [0u8; BLS_PK_LEN]));
  }

  /// A legacy key outside the subgroup is valid under the legacy scheme, and
  /// the invalid object under the basic scheme, which reads it as legacy.
  #[test]
  fn opposite_scheme_bytes_are_invalid() {
    let legacy = BlsEagerPk::decode(&G1_OFF_SUBGROUP_CHIA, LEGACY);
    assert!(legacy.as_ref().is_ok_and(|pk| {
      pk.value().point() == Some(&BlsPoint::Exotic)
        && pk.to_bytes(LEGACY) == G1_OFF_SUBGROUP_CHIA
        && pk.to_bytes(BASIC) == G1_OFF_SUBGROUP_IETF
    }));
    let basic = BlsEagerPk::decode(&G1_OFF_SUBGROUP_CHIA, BASIC);
    assert!(basic.is_ok_and(|pk| !pk.is_valid()));
  }

  /// Bytes canonical under neither scheme fail with the error of their kind.
  #[rstest]
  #[case::x_eq_p(G1_X_EQ_PRIME_CHIA)]
  #[case::identity({
    let mut identity = [0u8; BLS_PK_LEN];
    identity[0] = 0xc0;
    identity
  })]
  fn non_canonical_bytes_fail(#[case] bytes: [u8; BLS_PK_LEN]) {
    for scheme in [LEGACY, BASIC] {
      assert_eq!(BlsEagerPk::decode(&bytes, scheme), Err(BlsError::InvalidPublicKey));
    }
    let mut identity = [0u8; BLS_SIG_LEN];
    identity[0] = 0xc0;
    assert_eq!(BlsEagerSig::decode(&identity, BASIC), Err(BlsError::InvalidSignature));
  }
}
