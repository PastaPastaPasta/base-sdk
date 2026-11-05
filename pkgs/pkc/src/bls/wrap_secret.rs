//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS secret keys decoded with the object that carries them.

use super::byte_bags::{BlsSkBytes, BLS_SK_LEN};
use super::error::BlsError;
use super::scheme_ctx::BlsSchemeKind;
use super::wrap_codec::{is_zero, sk_is_canonical};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use core::fmt::{self, Debug, Formatter};

/// A BLS secret key decoded with the object that carries it, a valid key or
/// the invalid object.
///
/// Secret keys are written alike under both schemes. The invalid object
/// encodes as zeros.
#[derive(Clone)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsEagerSecretKey {
  key: Option<BlsSkBytes>,
}

impl BlsEagerSecretKey {
  /// The invalid object.
  pub const fn invalid() -> Self {
    Self { key: None }
  }

  /// Decodes under `scheme`, as matching the reference implementation needs.
  ///
  /// The legacy scheme reads keys modulo `r`, so the keys below `r` are
  /// canonical under it. The basic scheme refuses keys above `r`, so the keys
  /// up to `r` are canonical under it. Zero is canonical under neither.
  ///
  /// All-zero bytes give the invalid object. Bytes canonical under the
  /// scheme give the key. Bytes canonical only under the other scheme, `r`
  /// under the legacy scheme, give the invalid object.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the bytes are canonical under neither
  /// scheme, every key above `r`.
  pub fn decode(bytes: &[u8; BLS_SK_LEN], scheme: BlsSchemeKind) -> Result<Self, BlsError> {
    if sk_is_canonical(bytes, scheme) {
      Ok(Self {
        key: Some(BlsSkBytes::from_bytes(*bytes)),
      })
    } else if is_zero(bytes) || sk_is_canonical(bytes, scheme.opposite()) {
      Ok(Self::invalid())
    } else {
      Err(BlsError::InvalidSecretKey)
    }
  }

  /// Whether the object is valid.
  pub fn is_valid(&self) -> bool {
    self.key.is_some()
  }

  /// The key of a valid object.
  pub fn key(&self) -> Option<&BlsSkBytes> {
    self.key.as_ref()
  }

  /// Encodes under either scheme, zeros when invalid, wiped when the
  /// returned value drops.
  pub fn to_bytes(&self) -> Zeroizing<[u8; BLS_SK_LEN]> {
    self
      .key
      .as_ref()
      .map_or_else(|| Zeroizing::new([0u8; BLS_SK_LEN]), BlsSkBytes::to_bytes)
  }
}

impl Debug for BlsEagerSecretKey {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.write_str("BlsEagerSecretKey(..)")
  }
}

impl Eq for BlsEagerSecretKey {}

/// The same validity and, for valid objects, the same key, compared in
/// constant time.
impl PartialEq for BlsEagerSecretKey {
  fn eq(&self, other: &Self) -> bool {
    match (&self.key, &other.key) {
      (Some(a), Some(b)) => bool::from(a.as_bytes().ct_eq(b.as_bytes())),
      (a, b) => a.is_none() && b.is_none(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{wrapper_vectors, EagerOutcome, EagerVector, GROUP_ORDER};
  use crate::prelude::*;

  use dash_dev::arr_from_hex;
  use rstest::rstest;

  const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
  const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

  /// `r` with its last byte, 0x01, replaced.
  fn order_with_last(last: u8) -> [u8; BLS_SK_LEN] {
    let mut key = GROUP_ORDER;
    key[BLS_SK_LEN - 1] = last;
    key
  }

  /// The keys at each end of each scheme's range: valid, invalid or failed.
  #[rstest]
  #[case::zero([0u8; BLS_SK_LEN], Ok(false), Ok(false))]
  #[case::r_minus_1(order_with_last(0x00), Ok(true), Ok(true))]
  #[case::r(GROUP_ORDER, Ok(false), Ok(true))]
  #[case::r_plus_1(
    order_with_last(0x02),
    Err(BlsError::InvalidSecretKey),
    Err(BlsError::InvalidSecretKey)
  )]
  fn range_ends(
    #[case] key: [u8; BLS_SK_LEN],
    #[case] legacy: Result<bool, BlsError>,
    #[case] basic: Result<bool, BlsError>,
  ) {
    for (scheme, expected) in [(LEGACY, legacy), (BASIC, basic)] {
      let written = BlsEagerSecretKey::decode(&key, scheme).map(|sk| (sk.is_valid(), *sk.to_bytes()));
      let expected = expected.map(|valid| (valid, if valid { key } else { [0u8; BLS_SK_LEN] }));
      assert_eq!(written, expected, "{scheme:?}");
    }
  }

  /// Keys that differ in the last byte only differ, and the key is redacted.
  #[test]
  fn keys_compare_and_are_redacted() {
    let a = BlsEagerSecretKey::decode(&[0x5a; BLS_SK_LEN], BASIC);
    let b = BlsEagerSecretKey::decode(&order_with_last(0x00), BASIC);
    let c = BlsEagerSecretKey::decode(&order_with_last(0x01), BASIC);
    assert!(b != c && a == a.clone() && b != Ok(BlsEagerSecretKey::invalid()));
    assert!(a.is_ok_and(|sk| sk.is_valid() && !format!("{sk:?}").contains("5a5a")));
  }

  /// Every `bls_wrapper` secret key input reads as in the reference
  /// implementation.
  #[test]
  fn eager_reads_match_reference() {
    for v in wrapper_vectors::<EagerVector>("sk", "eager") {
      let input: [u8; BLS_SK_LEN] = arr_from_hex(&v.input);
      for scheme in [LEGACY, BASIC] {
        let label = format!("sk {} {} {scheme:?}", v.class, v.input);
        let expected = match v.outcome(scheme) {
          EagerOutcome::Throw => Err(BlsError::InvalidSecretKey),
          EagerOutcome::Invalid => Ok([0u8; BLS_SK_LEN]),
          EagerOutcome::Valid => Ok(v.other(scheme).map_or([0u8; BLS_SK_LEN], arr_from_hex)),
        };
        let written = BlsEagerSecretKey::decode(&input, scheme).map(|sk| *sk.to_bytes());
        assert_eq!(written, expected, "{label}");
        if v.outcome(scheme) == EagerOutcome::Valid {
          assert_eq!(written, Ok(input), "{label}");
        }
      }
    }
  }
}
