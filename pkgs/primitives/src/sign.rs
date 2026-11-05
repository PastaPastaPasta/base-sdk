//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signature checks shared by the signed payloads.

use crate::prelude::*;
use crate::{QuorumHash, Transaction};

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_params::LlmqType;
use dash_pkc::bls::{BlsError, BlsPkBytes, BlsScheme, BlsSigBytes};
use dash_pkc::ecdsa::{EcdsaError, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature, ECDSA_REC_SIG_LEN};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, EncodeBuf};
use dash_types::{Hashable, Numeric};

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

/// Writes the version, type and lock time of `tx`.
pub(crate) fn write_tx_header(tx: &Transaction, buf: &mut impl EncodeBuf) {
  tx.version().encode(buf);
  tx.tx_type().to_base().encode(buf);
  tx.lock_time().encode(buf);
}

/// The hash of `tx` with its extra payload replaced by `payload`.
pub(crate) fn tx_hash_with(tx: &Transaction, payload: &impl BaseCodec) -> Hash256 {
  let mut extra = Vec::new();
  payload.encode(&mut extra);
  let tx = Transaction::new(
    tx.version(),
    tx.tx_type(),
    tx.inputs().clone(),
    tx.outputs().clone(),
    tx.lock_time(),
    extra,
  );
  Hash256::from_lendian(tx.instance_hash().to_lendian())
}

/// The id of a quorum signing request, the hash of `prefix` and `n`.
pub(crate) fn request_id(prefix: &str, n: &impl BaseCodec) -> Hash256 {
  let mut buf = Vec::new();
  String::from(prefix).encode(&mut buf);
  n.encode(&mut buf);
  Hash256::from_lendian(sha256d(&buf))
}

/// The digest a quorum of `llmq_type` signs for request `id` over the
/// message hash `msg_hash`.
pub fn llmq_sig_hash(llmq_type: LlmqType, quorum_hash: &QuorumHash, id: &Hash256, msg_hash: &Hash256) -> Hash256 {
  let mut buf = Vec::new();
  llmq_type.encode(&mut buf);
  quorum_hash.encode(&mut buf);
  id.encode(&mut buf);
  msg_hash.encode(&mut buf);
  Hash256::from_lendian(sha256d(&buf))
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

/// [`verify_compact`], refusing a header that is not canonical or a high S.
///
/// # Errors
///
/// Returns `InvalidSignature` for a non-canonical header or high S, and
/// otherwise the errors from [`verify_compact`].
pub(crate) fn verify_compact_canonical(
  digest: &[u8],
  sig: &[u8; ECDSA_REC_SIG_LEN],
  key: &PubKeyHash,
) -> Result<(), EcdsaError> {
  let bytes = EcdsaRecSigBytes::from_bytes(*sig).ok_or(EcdsaError::InvalidSignature)?;
  if !EcdsaRecSignature::try_from(bytes)?.signature().is_low_s() {
    return Err(EcdsaError::InvalidSignature);
  }
  verify_compact(digest, sig, key)
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

  use dash_dev::arr_from_hex;
  use dash_pkc::bls::BlsSecretKey;
  use dash_pkc::ecdsa::{Compression, EcdsaSecretKey};
  use dash_types::Signable;
  use rstest::rstest;

  /// Signs `digest` itself, returning the key id and the compact signature.
  pub(crate) fn ecdsa_sign(seed: u8, digest: &[u8; 32]) -> (PubKeyHash, [u8; 65]) {
    let sk = EcdsaSecretKey::from_bytes(&[seed; 32], Compression::Compressed).unwrap();
    (
      sk.public_key().hash(),
      EcdsaRecSigBytes::from(sk.sign_recoverable(digest)).to_bytes(),
    )
  }

  /// A consent signature of type `T` over `ctx` is stored only when it
  /// verifies under the signer's key, leaves the digest unchanged and is
  /// removed by a reset.
  pub(crate) fn consent_signs_the_payload<T>(ctx: &T::Context)
  where
    T: Default + Signable<Key = PubKeyHash, Error = EcdsaError>,
  {
    let mut consent = T::default();
    let digest = <[u8; 32]>::try_from(consent.payload(ctx)).unwrap();
    let (key, sig) = ecdsa_sign(1, &digest);
    let (other, _) = ecdsa_sign(2, &digest);

    assert_eq!(consent.verify(&key, ctx), Some(EcdsaError::InvalidSignature));
    assert_eq!(consent.set_signature(&sig, &other, ctx), Err(EcdsaError::VerifyFailed));
    assert_eq!(
      consent.set_signature(&sig[1..], &key, ctx),
      Err(EcdsaError::InvalidSignature)
    );
    assert_eq!(consent.set_signature(&sig, &key, ctx), Ok(()));
    assert_eq!(consent.verify(&key, ctx), None);
    assert_eq!(consent.verify(&other, ctx), Some(EcdsaError::VerifyFailed));
    assert_eq!(consent.payload(ctx), digest);

    consent.reset_signature();
    assert_eq!(consent.verify(&key, ctx), Some(EcdsaError::InvalidSignature));
  }

  /// The high-S twin of a compact signature recovers the same key, so the
  /// plain check takes it and the canonical check refuses it.
  #[rstest]
  fn canonical_refuses_the_high_s_twin() {
    let digest = [7_u8; 32];
    let (key, low) = ecdsa_sign(1, &digest);
    let high = arr_from_hex(
      "20001af75f8a0ececcc4af0ccdbcccc1a81656eca444e3484151212ad1823ae1\
       22833f8b7a45a58860e0edf76f6f1b4feb88812c0bca608b262d11ac9ec06549f4",
    );
    assert_eq!(verify_compact(&digest, &high, &key), Ok(()));
    assert_eq!(verify_compact_canonical(&digest, &low, &key), Ok(()));
    assert_eq!(
      verify_compact_canonical(&digest, &high, &key),
      Err(EcdsaError::InvalidSignature)
    );
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
