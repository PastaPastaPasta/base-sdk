//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 recoverable signature.

use super::error::EcdsaError;
use super::sig_bytes::{EcdsaSigBytes, ECDSA_SIG_LEN};
use super::sig_ops::EcdsaSignature;
use super::sig_rec_bytes::{CompactFlags, EcdsaRecSigBytes};
use super::Compression;

#[cfg(feature = "codec")]
use dash_num::Hash256;
use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::{dlgt_codec, type_id::TypeId};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};

/// An ECDSA signature with recovery id and compression metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EcdsaRecSigBytes", try_from = "EcdsaRecSigBytes"))]
pub struct EcdsaRecSignature {
  sig: EcdsaSignature,
  flags: CompactFlags,
}

#[cfg(feature = "codec")]
dlgt_codec!(EcdsaRecSignature => EcdsaRecSigBytes, Hash256, EcdsaError, ECDSA_SIG_LEN + 2);

impl EcdsaRecSignature {
  pub(super) fn from_inner(inner: Signature, recovery_id: RecoveryId, compressed: Compression) -> Self {
    Self {
      sig: EcdsaSignature::from_inner(inner),
      flags: CompactFlags::from_parts(recovery_id.to_u8(), compressed),
    }
  }

  /// Attach recovery metadata to a plain signature.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidRecoveryId`] if `recovery_id` is not in
  /// `0..=3`.
  pub fn from_parts(sig: EcdsaSignature, recovery_id: u8, compressed: Compression) -> Result<Self, EcdsaError> {
    let flags = CompactFlags::new(recovery_id, compressed).ok_or(EcdsaError::InvalidRecoveryId)?;
    Ok(Self { sig, flags })
  }

  /// Whether the signing key was compressed.
  pub fn is_compressed(&self) -> bool {
    self.flags.is_compressed()
  }

  /// Return a signature with the S value normalised to the lower half of the
  /// curve order. Returns `None` if already normalised.
  pub fn normalize_s(&self) -> Option<Self> {
    // Negating S mirrors R across the X axis: X is unchanged and the Y parity
    // flips, so the recovery id toggles its low bit.
    let sig = self.sig.normalize_s()?;
    Some(Self {
      sig,
      flags: CompactFlags::from_parts(self.recovery_id() ^ 1, Compression::from(self.is_compressed())),
    })
  }

  /// Recovery ID.
  pub fn recovery_id(&self) -> u8 {
    self.flags.recovery_id()
  }

  /// The recovery id in the form the backend expects.
  ///
  /// Infallible, like the masked constructor it uses; `CompactFlags` encodes
  /// only ids in `0..=3`, so nothing is ever masked away.
  pub(super) const fn backend_recovery_id(&self) -> RecoveryId {
    RecoveryId::from_u8_masked(self.flags.recovery_id())
  }

  /// The plain signature without recovery metadata.
  pub fn signature(&self) -> &EcdsaSignature {
    &self.sig
  }

  /// Serialize as 64-byte compact format (r || s).
  pub fn to_compact(&self) -> [u8; ECDSA_SIG_LEN] {
    self.sig.to_bytes()
  }
}

impl AsRef<EcdsaSignature> for EcdsaRecSignature {
  fn as_ref(&self) -> &EcdsaSignature {
    &self.sig
  }
}

// Infallible: `CompactFlags` covers every (id, compression) pair.
type_cvrt!(From<EcdsaRecSignature> for EcdsaRecSigBytes, |rec| {
  Self::from_flags(EcdsaSigBytes::from(rec.signature()), rec.flags)
});

type_cvrt!(From<EcdsaRecSignature> for EcdsaSignature, |rec| {
  *rec.signature()
});

type_cvrt!(TryFrom<EcdsaRecSigBytes> for EcdsaRecSignature, EcdsaError, |bytes| {
  Ok(Self {
    sig: EcdsaSignature::try_from(bytes.signature())?,
    flags: bytes.flags(),
  })
});

type_cvrt!(TryFrom<EcdsaRecSignature> for RecoverableSignature, EcdsaError, |rec| {
  RecoverableSignature::from_compact(&rec.to_compact(), rec.backend_recovery_id())
    .map_err(|_| EcdsaError::InvalidSignature)
});

// The backend type holds only the scalars and the recovery id, the compression
// flag doesn't make it through and it is assumed to be compressed. To preserve
// the compression flag, use `from_parts`.
type_cvrt!(From<RecoverableSignature> for EcdsaRecSignature, |rec| {
  let (rid, _) = rec.serialize_compact();
  Self::from_inner(rec.to_standard(), rid, Compression::Compressed)
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{
    Compression, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature, EcdsaSecretKey, EcdsaSigBytes, EcdsaSignature,
  };

  #[cfg(feature = "serde")]
  use dash_dev::assert_json_rt;
  use rstest::*;

  /// The infallible bit-split must agree with the fallible byte parse it
  /// replaced, for every id the flags can hold.
  #[rstest]
  #[case(0)]
  #[case(1)]
  #[case(2)]
  #[case(3)]
  fn backend_recovery_id_matches_byte(#[case] id: u8, alice_sig: EcdsaSignature) {
    let rec = EcdsaRecSignature::from_parts(alice_sig, id, Compression::Compressed).unwrap();
    assert_eq!(rec.backend_recovery_id().to_u8(), id);
  }

  #[rstest]
  fn bag_roundtrip(alice_rec_sig: EcdsaRecSignature) {
    let bag = EcdsaRecSigBytes::from(&alice_rec_sig);
    let restored = EcdsaRecSignature::try_from(bag).unwrap();
    assert_eq!(restored, alice_rec_sig);
  }

  #[rstest]
  fn conversions_commute(alice_rec_sig: EcdsaRecSignature) {
    // Both paths to the plain bag must agree: drop metadata then serialize, or
    // serialize then strip the header.
    let via_ops = EcdsaSigBytes::from(EcdsaSignature::from(alice_rec_sig));
    let via_bag = EcdsaSigBytes::from(EcdsaRecSigBytes::from(&alice_rec_sig));
    assert_eq!(via_ops, via_bag);
  }

  #[rstest]
  fn from_parts_rejects_out_of_range_id(alice_sig: EcdsaSignature) {
    assert!(EcdsaRecSignature::from_parts(alice_sig, 4, Compression::Compressed).is_err());
    assert!(EcdsaRecSignature::from_parts(alice_sig, 255, Compression::Compressed).is_err());
  }

  #[rstest]
  #[case(0)]
  #[case(1)]
  #[case(2)]
  #[case(3)]
  fn recovery_id_roundtrip(#[case] id: u8, alice_sig: EcdsaSignature) {
    let rec = EcdsaRecSignature::from_parts(alice_sig, id, Compression::Compressed).unwrap();
    assert_eq!(rec.recovery_id(), id);
  }

  #[rstest]
  fn normalize_s_flips_recovery_id(alice_rec_sig: EcdsaRecSignature) {
    // Library signs with low-S, so normalize_s returns None. To test the flip
    // we would need a high-S sig; verify the invariant instead: if normalize_s
    // returns Some, the recovery_id must differ.
    if let Some(normed) = alice_rec_sig.normalize_s() {
      assert_ne!(normed.recovery_id(), alice_rec_sig.recovery_id());
    }
  }

  #[rstest]
  fn normalize_s_flips_high_s_recoverable_signature(alice_pk: EcdsaPublicKey, alice_rec_sig: EcdsaRecSignature) {
    let compact = alice_rec_sig.to_compact();
    let mut high_bytes = [0u8; 64];
    high_bytes[..32].copy_from_slice(&compact[..32]);
    high_bytes[32..].copy_from_slice(&negate_scalar(&compact[32..]));
    let high_sig = EcdsaSignature::from_bytes(&high_bytes).unwrap();

    let flipped_id = alice_rec_sig.recovery_id() ^ 1;
    let high_rec =
      EcdsaRecSignature::from_parts(high_sig, flipped_id, Compression::from(alice_rec_sig.is_compressed())).unwrap();

    let normalized = high_rec.normalize_s().unwrap();
    assert_eq!(normalized.recovery_id(), alice_rec_sig.recovery_id());
    assert_eq!(normalized, alice_rec_sig);
    assert_eq!(EcdsaPublicKey::recover(&MSG, &normalized).unwrap(), alice_pk);
  }

  #[rstest]
  fn verifies_without_downcast(alice_pk: EcdsaPublicKey, alice_rec_sig: EcdsaRecSignature) {
    assert!(alice_pk.verify_digest(&MSG, alice_rec_sig).is_ok());
    assert!(alice_pk.verify_digest(&MSG, alice_rec_sig.signature()).is_ok());
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip(alice_rec_sig: EcdsaRecSignature) {
    assert_json_rt(&alice_rec_sig);
  }

  #[rstest]
  fn uncompressed_recsig_keeps_flag() {
    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK, Compression::Uncompressed).unwrap();
    let rec = sk.sign_recoverable(&MSG);
    assert!(!rec.is_compressed());

    // Recovery carries the flag onto the key it rebuilds.
    let pk = EcdsaPublicKey::recover(&MSG, &rec).unwrap();
    assert!(!pk.is_compressed());
    assert_eq!(pk, sk.public_key());

    // The backend type doesn't store the flag, so the round trip comes back
    // compressed.
    let inner = secp256k1::ecdsa::RecoverableSignature::try_from(&rec).unwrap();
    let back = EcdsaRecSignature::from(inner);
    assert_eq!(back.signature(), rec.signature());
    assert_eq!(back.recovery_id(), rec.recovery_id());
    assert!(back.is_compressed());
  }

  #[rstest]
  fn backend_roundtrip_keeps_recovery_id(alice_rec_sig: EcdsaRecSignature) {
    let inner = secp256k1::ecdsa::RecoverableSignature::try_from(&alice_rec_sig).unwrap();
    let (rid, compact) = inner.serialize_compact();
    assert_eq!(compact, alice_rec_sig.to_compact());
    assert_eq!(rid.to_u8(), alice_rec_sig.recovery_id());
    assert_eq!(EcdsaRecSignature::from(inner), alice_rec_sig);
  }
}
