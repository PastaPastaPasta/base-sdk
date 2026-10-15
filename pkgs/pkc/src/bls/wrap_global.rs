//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS fields that take Dash Core's process-wide scheme, kept as wire bytes
//! until the scheme is known.

use super::group::{G1, G2};
use super::scheme_ctx::{BlsCtx, BlsSchemeKind};
use super::wrap_codec::{is_zero, BlsWirePoint};
use super::wrap_eager::{BlsDecodeError, BlsEager};
use super::wrap_value::BlsValue;
use super::{BLS_PK_LEN, BLS_SIG_LEN};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::DisplayHex;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// A BLS field whose scheme Core takes from its process-wide flag, kept as
/// its wire bytes.
///
/// Whether Core's `CBLSWrapper::Unserialize` throws does not depend on the
/// flag: bytes other than zeros throw when they are canonical in neither
/// scheme. [`Self::decode`] applies that check alone, so the object carrying
/// the field decodes without the flag. [`Self::get`] gives the object Core
/// reads under a flag.
///
/// The field encodes as its wire bytes. Core serializes the object under the
/// flag at that time; [`Self::from_eager`] gives those bytes, which Core may
/// not read back.
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsGlobal<K: BlsWirePoint<N>, const N: usize> {
  bytes: [u8; N],
  kind: PhantomData<fn() -> K>,
}

/// A public key under Core's process-wide scheme.
pub type BlsGlobalPk = BlsGlobal<G1, BLS_PK_LEN>;
/// A signature under Core's process-wide scheme.
pub type BlsGlobalSig = BlsGlobal<G2, BLS_SIG_LEN>;

impl<K: BlsWirePoint<N>, const N: usize> BlsGlobal<K, N> {
  /// Keeps bytes Core reads under either flag without throwing: zeros, or
  /// bytes canonical in at least one scheme.
  ///
  /// # Errors
  ///
  /// Returns [`BlsDecodeError`] when the bytes are canonical in neither
  /// scheme, the identity encoding included.
  pub fn decode(bytes: &[u8; N]) -> Result<Self, BlsDecodeError> {
    let readable =
      is_zero(bytes) || K::is_canonical(bytes, BlsSchemeKind::Basic) || K::is_canonical(bytes, BlsSchemeKind::Legacy);
    if readable {
      Ok(Self::from_wire(*bytes))
    } else {
      Err(BlsDecodeError)
    }
  }

  /// The object Core reads under `ctx`'s flag: valid when the bytes are
  /// canonical in that scheme, otherwise invalid.
  ///
  /// Every call decodes the bytes in full, decompressing the point and,
  /// under the basic scheme, checking its subgroup, so keep the result
  /// rather than call it again.
  pub fn get(&self, ctx: BlsCtx) -> BlsEager<K, N> {
    let scheme = ctx.scheme();
    let value = if is_zero(&self.bytes) {
      None
    } else {
      BlsValue::from_canonical(&self.bytes, scheme)
    };
    BlsEager::new(value.unwrap_or_else(BlsValue::invalid), scheme)
  }

  /// The field Core writes when it serializes `field` under `ctx`'s flag;
  /// zeros when `field` is invalid.
  ///
  /// Core can write bytes its reader throws on: a G1 point valid only under
  /// the legacy scheme can have a basic encoding canonical in neither. These
  /// are those bytes, which [`Self::decode`] rejects.
  pub fn from_eager(field: &BlsEager<K, N>, ctx: BlsCtx) -> Self {
    Self::from_wire(field.to_bytes(ctx.scheme()))
  }

  /// The wire bytes.
  pub fn to_bytes(&self) -> [u8; N] {
    self.bytes
  }

  fn from_wire(bytes: [u8; N]) -> Self {
    Self {
      bytes,
      kind: PhantomData,
    }
  }
}

impl<K: BlsWirePoint<N>, const N: usize> Clone for BlsGlobal<K, N> {
  fn clone(&self) -> Self {
    Self::from_wire(self.bytes)
  }
}

impl<K: BlsWirePoint<N>, const N: usize> Debug for BlsGlobal<K, N> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_tuple("BlsGlobal").field(&self.bytes.as_hex()).finish()
  }
}

impl<K: BlsWirePoint<N>, const N: usize> Eq for BlsGlobal<K, N> {}

impl<K: BlsWirePoint<N>, const N: usize> Hash for BlsGlobal<K, N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.bytes.hash(state);
  }
}

/// Equal wire bytes.
impl<K: BlsWirePoint<N>, const N: usize> PartialEq for BlsGlobal<K, N> {
  fn eq(&self, other: &Self) -> bool {
    self.bytes == other.bytes
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  #[test]
  fn zeros_read_as_the_invalid_object_under_both_flags() {
    let zeros = BlsGlobalSig::decode(&[0u8; BLS_SIG_LEN]).unwrap();
    for ctx in [BlsCtx::BASIC, BlsCtx::LEGACY] {
      let eager = zeros.get(ctx);
      assert!(!eager.is_valid());
      assert_eq!(eager.scheme(), ctx.scheme());
    }
  }

  #[test]
  fn identity_throws() {
    let mut identity = [0u8; BLS_SIG_LEN];
    identity[0] = 0xc0;
    assert_eq!(BlsGlobalSig::decode(&identity), Err(BlsDecodeError));
  }
}
