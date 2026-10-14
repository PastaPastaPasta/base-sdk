//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signature checks shared by the signed payloads.

use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_pkc::bls::{BlsError, BlsPkBytes, BlsScheme, BlsSigBytes};
use dash_pkc::ecdsa::{EcdsaError, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature, ECDSA_REC_SIG_LEN};
use dash_script::PubKeyHash;
use dash_types::codec::BaseCodec;
use dash_types::Hashable;

/// Prefix hashed ahead of a signed message.
pub const MESSAGE_MAGIC: &str = "DarkCoin Signed Message:\n";

/// Double SHA-256 of `data`.
pub(crate) fn sha256d(data: &[u8]) -> [u8; 32] {
  sha256d::Hash::hash(data).to_byte_array()
}

/// Double SHA-256 of the encoded `payload` without `sig`, its trailing field.
pub(crate) fn unsigned_digest(payload: &impl BaseCodec, sig: &impl BaseCodec) -> [u8; 32] {
  let mut image = Vec::new();
  payload.encode(&mut image);
  let mut tail = Vec::new();
  sig.encode(&mut tail);
  image.truncate(image.len().saturating_sub(tail.len()));
  sha256d(&image)
}

/// Digest signed for the message `msg`.
pub(crate) fn message_digest(msg: &[u8]) -> [u8; 32] {
  let mut buf = Vec::new();
  String::from(MESSAGE_MAGIC).encode(&mut buf);
  msg.to_vec().encode(&mut buf);
  sha256d(&buf)
}

/// Checks a compact signature over `digest` against the key id `key`.
///
/// The header is masked first, so a non-canonical header still verifies.
///
/// # Errors
///
/// Returns `InvalidSignature` when `sig` holds no valid scalars,
/// `RecoveryFailed` when no key recovers, and `VerifyFailed` when `digest` is
/// not 32 bytes or the recovered key has another id.
pub(crate) fn verify_compact(digest: &[u8], sig: &[u8; ECDSA_REC_SIG_LEN], key: &PubKeyHash) -> Result<(), EcdsaError> {
  let digest = <&[u8; 32]>::try_from(digest).map_err(|_| EcdsaError::VerifyFailed)?;
  let rec = EcdsaRecSignature::try_from(EcdsaRecSigBytes::from_bytes_mask(*sig))?;
  if EcdsaPublicKey::recover(digest, &rec)?.hash() == *key {
    Ok(())
  } else {
    Err(EcdsaError::VerifyFailed)
  }
}

/// Checks a BLS signature over `digest` under scheme `S`.
///
/// # Errors
///
/// Returns `InvalidPublicKey` or `InvalidSignature` when `S` refuses the
/// bytes, and `VerifyFailed` when `digest` is not 32 bytes or the signature
/// does not verify.
pub(crate) fn verify_bls<S: BlsScheme>(digest: &[u8], sig: &BlsSigBytes, key: &BlsPkBytes) -> Result<(), BlsError> {
  let digest = <&[u8; 32]>::try_from(digest).map_err(|_| BlsError::VerifyFailed)?;
  key.to::<S>()?.verify_digest(digest, &sig.to::<S>()?)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
pub(crate) mod tests {
  use super::*;

  use dash_pkc::bls::BlsSecretKey;
  use dash_pkc::ecdsa::{Compression, EcdsaSecretKey};
  use rstest::rstest;

  /// Signs `digest` itself, returning the key id and the compact signature.
  pub(crate) fn ecdsa_sign(seed: u8, digest: &[u8; 32]) -> (PubKeyHash, [u8; 65]) {
    let sk = EcdsaSecretKey::from_bytes(&[seed; 32], Compression::Compressed).unwrap();
    (
      sk.public_key().hash(),
      EcdsaRecSigBytes::from(sk.sign_recoverable(digest)).to_bytes(),
    )
  }

  /// Signs `digest` under scheme `S`, returning the public key and signature.
  pub(crate) fn bls_sign<S: BlsScheme>(seed: u8, digest: &[u8; 32]) -> (BlsPkBytes, [u8; 96]) {
    let sk = BlsSecretKey::<S>::from_ikm(&[seed; 32]).unwrap();
    (BlsPkBytes::from(sk.public_key()), sk.sign_digest(digest).to_bytes())
  }

  #[rstest]
  fn compact_checks_the_key_id() {
    let (key, sig) = ecdsa_sign(1, &[7; 32]);
    let (other, _) = ecdsa_sign(2, &[7; 32]);

    assert_eq!(verify_compact(&[7; 32], &sig, &key), Ok(()));
    assert_eq!(verify_compact(&[7; 32], &sig, &other), Err(EcdsaError::VerifyFailed));
  }
}
