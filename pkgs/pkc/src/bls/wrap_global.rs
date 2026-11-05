//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS fields read under a context, kept as bytes until it is known.

use super::byte_bags::{BLS_PK_LEN, BLS_SIG_LEN};
use super::error::BlsError;
use super::group::{G1, G2};
use super::scheme_ctx::{BlsCtx, BlsSchemeKind};
use super::wrap_codec::{is_zero, BlsWire};
use super::wrap_eager::BlsEager;
use super::wrap_value::BlsValue;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::DisplayHex;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// A BLS point whose scheme is that of a [`BlsCtx`], kept as its bytes.
///
/// Whether [`BlsEager::decode`] fails does not depend on the scheme: bytes
/// other than zeros fail when they are canonical under neither scheme.
/// [`Self::decode`] applies that check alone, so the object that carries the
/// field decodes without a context. [`Self::get`] gives the field under one.
///
/// The field encodes as the field [`Self::get`] gives under the context
/// does: as the bytes when they are canonical under its scheme, otherwise as
/// zeros.
///
/// `==` compares the bytes. Comparing as the reference implementation does
/// goes through the fields [`Self::get`] gives.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsGlobal<K: BlsWire<N>, const N: usize> {
  bytes: [u8; N],
  kind: PhantomData<fn() -> K>,
}

/// A public key under a context.
pub type BlsGlobalPk = BlsGlobal<G1, BLS_PK_LEN>;
/// A signature under a context.
pub type BlsGlobalSig = BlsGlobal<G2, BLS_SIG_LEN>;

impl<K: BlsWire<N>, const N: usize> BlsGlobal<K, N> {
  /// Keeps bytes that decode under either scheme: zeros, or bytes canonical
  /// under at least one scheme.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` or `InvalidSignature` when the bytes are
  /// canonical under neither scheme, the identity encoding included.
  pub fn decode(bytes: &[u8; N]) -> Result<Self, BlsError> {
    let decodes =
      is_zero(bytes) || K::is_canonical(bytes, BlsSchemeKind::Basic) || K::is_canonical(bytes, BlsSchemeKind::Legacy);
    if decodes {
      Ok(Self::from_bytes(*bytes))
    } else {
      Err(K::INVALID)
    }
  }

  /// The field decoded under `ctx`: valid when the bytes are canonical under
  /// its scheme, otherwise the invalid object, which encodes as zeros.
  ///
  /// Every call decodes the bytes in full, decompressing the point and
  /// checking its subgroup, so keep the result rather than call it again.
  pub fn get(&self, ctx: BlsCtx) -> BlsEager<K, N> {
    let value = BlsValue::from_canonical(&self.bytes, ctx.scheme()).unwrap_or_else(BlsValue::invalid);
    BlsEager::new(value)
  }

  fn from_bytes(bytes: [u8; N]) -> Self {
    Self {
      bytes,
      kind: PhantomData,
    }
  }
}

impl<K: BlsWire<N>, const N: usize> Clone for BlsGlobal<K, N> {
  fn clone(&self) -> Self {
    Self::from_bytes(self.bytes)
  }
}

impl<K: BlsWire<N>, const N: usize> Debug for BlsGlobal<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_tuple("BlsGlobal").field(&self.bytes.as_hex()).finish()
  }
}

impl<K: BlsWire<N>, const N: usize> Eq for BlsGlobal<K, N> {}

impl<K: BlsWire<N>, const N: usize> Hash for BlsGlobal<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.bytes.hash(state);
  }
}

/// The same bytes.
impl<K: BlsWire<N>, const N: usize> PartialEq for BlsGlobal<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.bytes == other.bytes
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{wrapper_vectors, EagerOutcome, EagerVector};
  use crate::prelude::*;

  use dash_dev::arr_from_hex;
  use rstest::rstest;

  #[test]
  fn zeros_are_invalid_under_both_contexts() {
    let zeros = BlsGlobalSig::decode(&[0u8; BLS_SIG_LEN]).unwrap();
    for ctx in [BlsCtx::BASIC, BlsCtx::LEGACY] {
      let eager = zeros.get(ctx);
      assert!(!eager.is_valid());
      assert_eq!(eager.to_bytes(ctx.scheme()), [0u8; BLS_SIG_LEN]);
    }
  }

  #[test]
  fn identity_fails() {
    let mut identity = [0u8; BLS_SIG_LEN];
    identity[0] = 0xc0;
    assert_eq!(BlsGlobalSig::decode(&identity), Err(BlsError::InvalidSignature));
  }

  /// `x = 0` with the legacy sign bit set is valid under the legacy context
  /// only. The field's basic encoding, with bits 0x80 and 0x20 set, is
  /// canonical under neither scheme.
  #[test]
  fn legacy_point_is_valid_under_the_legacy_context_only() {
    let mut legacy = [0u8; BLS_PK_LEN];
    legacy[0] = 0x80;
    let global = BlsGlobalPk::decode(&legacy).unwrap();
    let field = global.get(BlsCtx::LEGACY);
    assert!(field.is_valid());
    assert_eq!(field.to_bytes(BlsSchemeKind::Legacy), legacy);
    assert!(!global.get(BlsCtx::BASIC).is_valid());

    let mut basic = legacy;
    basic[0] = 0xa0;
    assert_eq!(field.to_bytes(BlsSchemeKind::Basic), basic);
    assert_eq!(BlsGlobalPk::decode(&basic), Err(BlsError::InvalidPublicKey));
  }

  /// Every `bls_wrapper` key and signature input decodes unless the eager
  /// read fails under both schemes, and gives under each context what the
  /// eager read under its scheme gives.
  fn assert_global_reads<K: BlsWire<N>, const N: usize>(kind: &str) {
    for v in wrapper_vectors::<EagerVector>(kind, "eager") {
      let label = format!("{kind} {} {}", v.class, v.input);
      let input: [u8; N] = arr_from_hex(&v.input);
      let fails = v.outcome(BlsSchemeKind::Legacy) == EagerOutcome::Throw;
      assert_eq!(v.outcome(BlsSchemeKind::Basic) == EagerOutcome::Throw, fails, "{label}");
      let decoded = BlsGlobal::<K, N>::decode(&input);
      assert_eq!(decoded.is_err(), fails, "{label}");
      let Ok(global) = decoded else { continue };
      for ctx in [BlsCtx::LEGACY, BlsCtx::BASIC] {
        let field = global.get(ctx);
        let eager = BlsEager::decode(&input, ctx.scheme());
        assert_eq!(Ok(&field), eager.as_ref(), "{label} {ctx:?}");
      }
    }
  }

  #[rstest]
  #[case::pk(assert_global_reads::<G1, BLS_PK_LEN>, "pk")]
  #[case::sig(assert_global_reads::<G2, BLS_SIG_LEN>, "sig")]
  fn global_reads_match_reference(#[case] assertion: fn(&str), #[case] kind: &str) {
    assertion(kind);
  }
}
