//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar-field arithmetic and threshold helpers.

use super::blst_ffi;
use super::error::BlsError;
use super::group::{G1Affine, Point, G1, G2};
use super::scalar::{Fr, FR_BITS};
use super::schemes::BlsSchemeId;
use super::{BlsDhBytes, BlsShareId};
use crate::aes_cbc::{self, AES_BLOCK_LEN, AES_KEY_LEN};
use crate::prelude::*;
use crate::sealed::Sealed;

use blst::BLST_ERROR;
use ff::Field;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use core::fmt::Debug;

/// Multiplier width for the secure-aggregation weights.
///
/// The weight is an unreduced SHA-256 digest, so it needs the full width
/// rather than [`FR_BITS`].
const WEIGHT_BITS: usize = 256;

/// Map a blst verification outcome onto a [`BlsError`].
pub(crate) fn verify_ok(result: BLST_ERROR) -> Result<(), BlsError> {
  if result == BLST_ERROR::BLST_SUCCESS {
    Ok(())
  } else {
    Err(BlsError::VerifyFailed)
  }
}

/// BLS operations tied to a specific scheme.
#[doc(hidden)]
pub trait BlsScheme: BlsSchemeId + Sealed + Sized {
  /// Inner secret key representation.
  type InnerSk: Clone + Send + Sync;
  /// Inner public key representation.
  type InnerPk: Copy + Debug + PartialEq + Eq + Send + Sync;
  /// Inner signature representation.
  type InnerSig: Copy + Debug + PartialEq + Eq + Send + Sync;
  /// Hash-to-curve input accepted by signing and verification.
  type Msg<'a>: Copy + Send + Sync;

  /// Derive a secret key from input keying material.
  ///
  /// # Errors
  ///
  /// Returns `InvalidKeyMaterial` when `ikm` is too short, or
  /// `InvalidSecretKey` when the derived scalar is invalid.
  fn sk_from_ikm(ikm: &[u8]) -> Result<Self::InnerSk, BlsError>;

  /// Parse a secret key from a 32-byte big-endian scalar.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the bytes are not a valid scalar.
  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError>;

  /// Serialize a secret key to 32 big-endian bytes, wiped when dropped.
  fn sk_to_bytes(sk: &Self::InnerSk) -> Zeroizing<[u8; 32]>;

  /// Derive the public key corresponding to a secret key.
  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk;

  /// Wipe a secret key's scalar material in place.
  fn zeroize_sk(sk: &mut Self::InnerSk);

  /// Parse a public key from its 48-byte encoding.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the bytes are not a valid point.
  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError>;

  /// Serialize a public key to its 48-byte encoding.
  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48];

  /// Encode a G1 point in the scheme's 48-byte layout.
  fn g1_bytes(point: &G1Affine) -> [u8; 48];

  /// The IETF compressed form of `b`, a G1 encoding of a point other than
  /// infinity in the scheme's layout, with the same `x` and sign.
  fn pk_ietf_bytes(b: &[u8; 48]) -> [u8; 48];

  /// Lift a public key to a projective G1 point.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the key cannot be decoded to a point.
  fn pk_to_g1(pk: &Self::InnerPk) -> Result<G1, BlsError>;

  /// Lower a projective G1 point back to a public key.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the point is not a valid key.
  fn g1_to_pk(point: G1) -> Result<Self::InnerPk, BlsError>;

  /// Parse a signature from its 96-byte encoding.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the bytes are not a valid point.
  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError>;

  /// Serialize a signature to its 96-byte encoding.
  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96];

  /// Lift a signature to a projective G2 point.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the signature cannot be decoded.
  fn sig_to_g2(sig: &Self::InnerSig) -> Result<G2, BlsError>;

  /// Lower a projective G2 point back to a signature.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the point is not a valid signature.
  fn g2_to_sig(point: G2) -> Result<Self::InnerSig, BlsError>;

  /// Sign a message with the scheme's default augmentation.
  fn sign(sk: &Self::InnerSk, msg: Self::Msg<'_>) -> Self::InnerSig;

  /// Verify a signature over a message against a public key.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  fn verify(sig: &Self::InnerSig, msg: Self::Msg<'_>, pk: &Self::InnerPk) -> Result<(), BlsError>;

  /// Convert a 32-byte digest to the hash-to-curve input.
  fn digest_msg(digest: &[u8; 32]) -> Self::Msg<'_>;

  /// Build the hash-to-curve input for an arbitrary-length message.
  fn plaintext_msg(msg: &[u8]) -> Self::Msg<'_>;

  /// Compute the Diffie-Hellman shared key `sk * peer_pk`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the peer key or the product point
  /// is invalid.
  fn dh_exchange(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    let point = Self::pk_to_g1(peer_pk)?;
    let sk_bytes = Self::sk_to_bytes(sk);
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let product = point.mul_scalar(&sk_scalar.b, FR_BITS);
    sk_scalar.b.zeroize();
    Self::g1_to_pk(product)
  }

  /// Serialize a Diffie-Hellman product.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the shared secret cannot be derived.
  fn dh_bytes(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<BlsDhBytes, BlsError> {
    let shared = Self::dh_exchange(sk, peer_pk)?;
    Ok(BlsDhBytes::from_bytes(Self::pk_to_bytes(&shared)))
  }

  /// Derive the BLS-IES symmetric key from a Diffie-Hellman shared key.
  ///
  /// The key is the leading 32 bytes of the shared point's serialization, so
  /// it depends on the scheme and a blob is readable only by the scheme that
  /// wrote it.
  fn ies_key(shared: &BlsDhBytes) -> Zeroizing<[u8; AES_KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; AES_KEY_LEN]);
    key.copy_from_slice(&shared.as_bytes()[..AES_KEY_LEN]);
    key
  }

  /// Seal one plaintext to a recipient under an ephemeral key and IV.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` when the plaintext is empty or not a
  /// whole number of 16-byte blocks, or `InvalidPublicKey` when the shared
  /// secret cannot be derived.
  fn ies_seal(
    eph_sk: &Self::InnerSk,
    recipient: &Self::InnerPk,
    iv: &[u8; AES_BLOCK_LEN],
    plaintext: &[u8],
  ) -> Result<Vec<u8>, BlsError> {
    if plaintext.is_empty() {
      return Err(BlsError::InvalidPlaintextLength);
    }
    let key = Self::ies_key(&Self::dh_bytes(eph_sk, recipient)?);
    aes_cbc::encrypt(&key, iv, plaintext).ok_or(BlsError::InvalidPlaintextLength)
  }

  /// Open one ciphertext sealed to this key under an ephemeral key and IV.
  ///
  /// # Errors
  ///
  /// Returns `InvalidCiphertextLength` when the ciphertext is empty or not a
  /// whole number of 16-byte blocks, or `InvalidPublicKey` when the shared
  /// secret cannot be derived.
  fn ies_open(
    sk: &Self::InnerSk,
    eph_pk: &Self::InnerPk,
    iv: &[u8; AES_BLOCK_LEN],
    ciphertext: &[u8],
  ) -> Result<Zeroizing<Vec<u8>>, BlsError> {
    if ciphertext.is_empty() {
      return Err(BlsError::InvalidCiphertextLength);
    }
    let key = Self::ies_key(&Self::dh_bytes(sk, eph_pk)?);
    aes_cbc::decrypt(&key, iv, ciphertext).ok_or(BlsError::InvalidCiphertextLength)
  }

  /// Aggregate public keys into one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or
  /// `InvalidPublicKey` when a key fails to aggregate.
  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError>;

  /// Aggregate signatures into one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no signatures are given, or
  /// `InvalidSignature` when a signature fails to aggregate.
  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError>;

  /// Remove one signature from another.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when either signature or the difference
  /// fails to decode, or when the difference is the identity.
  fn sub_sig(sig: &Self::InnerSig, other: &Self::InnerSig) -> Result<Self::InnerSig, BlsError> {
    let difference = Self::sig_to_g2(sig)? - Self::sig_to_g2(other)?;
    // The identity signs nothing and verifies against everything paired with an
    // identity key.
    if difference.is_inf() {
      return Err(BlsError::InvalidSignature);
    }
    Self::g2_to_sig(difference)
  }

  /// Add `tweak` to a secret scalar, modulo the group order.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order or the
  /// sum is zero, which is the tweak that is this scalar's additive inverse.
  /// Returns `InvalidSecretKey` when `sk` is zero, which a key never is.
  fn add_tweak_sk(sk: &Self::InnerSk, tweak: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    let scalar = tweak_scalar(tweak)?;
    let bytes = Self::sk_to_bytes(sk);
    let mut current = Fr::from_bendian_reduce(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
    // A borrow reads the tweak in place, where `*scalar` would copy it out of
    // its wrapper onto the stack unwiped.
    let mut sum = current;
    sum += &*scalar;
    current.zeroize();

    // A zero sum hands back a key whoever chose the tweak already knows.
    if bool::from(sum.is_zero()) {
      return Err(BlsError::InvalidTweak);
    }

    // `Fr` is `Copy`, so it cannot wipe itself on the way out of scope.
    let tweaked = Self::sk_from_bytes(&Zeroizing::new(sum.to_bendian()));
    sum.zeroize();
    tweaked.map_err(|_| BlsError::InvalidTweak)
  }

  /// Multiply a secret scalar by `tweak`, modulo the group order.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order or is
  /// zero. The order is prime, so no other tweak can zero the product.
  /// Returns `InvalidSecretKey` when `sk` is zero, which a key never is.
  fn mul_tweak_sk(sk: &Self::InnerSk, tweak: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    let scalar = tweak_scalar(tweak)?;
    let bytes = Self::sk_to_bytes(sk);
    let mut current = Fr::from_bendian_reduce(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
    // A borrow reads the tweak in place, where `*scalar` would copy it out of
    // its wrapper onto the stack unwiped.
    let mut product = current;
    product *= &*scalar;
    current.zeroize();

    if bool::from(product.is_zero()) {
      return Err(BlsError::InvalidTweak);
    }

    // `Fr` is `Copy`, so it cannot wipe itself on the way out of scope.
    let tweaked = Self::sk_from_bytes(&product.to_bendian());
    product.zeroize();
    tweaked.map_err(|_| BlsError::InvalidTweak)
  }

  /// Negate a secret scalar, modulo the group order.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when `sk` is zero, which a key never is. The
  /// negation of a nonzero scalar is nonzero, so the backend takes it back.
  fn negate_sk(sk: &Self::InnerSk) -> Result<Self::InnerSk, BlsError> {
    let bytes = Self::sk_to_bytes(sk);
    let mut current = Fr::from_bendian_reduce(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
    let mut negated = -current;
    current.zeroize();

    // `Fr` is `Copy`, so it cannot wipe itself on the way out of scope.
    let result = Self::sk_from_bytes(&negated.to_bendian());
    negated.zeroize();
    result
  }

  /// Add `tweak * G` to a public key's point.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order or the
  /// sum is the point at infinity, and `InvalidPublicKey` when the key does
  /// not decode.
  fn add_tweak_pk(pk: &Self::InnerPk, tweak: &[u8; 32]) -> Result<Self::InnerPk, BlsError> {
    let scalar = tweak_scalar(tweak)?;
    Self::tweaked_g1_to_pk(Self::pk_to_g1(pk)? + <G1 as group::Group>::mul_by_generator(&scalar))
  }

  /// Multiply a public key's point by `tweak`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when `tweak` is not below the group order or the
  /// product is the point at infinity, and `InvalidPublicKey` when the key
  /// does not decode.
  fn mul_tweak_pk(pk: &Self::InnerPk, tweak: &[u8; 32]) -> Result<Self::InnerPk, BlsError> {
    let scalar = tweak_scalar(tweak)?;
    let mut blst_scalar = blst::blst_scalar::from(&*scalar);
    let product = Self::pk_to_g1(pk).map(|point| point.mul_scalar(&blst_scalar.b, FR_BITS));
    blst_scalar.b.zeroize();
    Self::tweaked_g1_to_pk(product?)
  }

  /// Negate a public key's point.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the key does not decode.
  fn negate_pk(pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    Self::g1_to_pk(-Self::pk_to_g1(pk)?)
  }

  /// Lower a tweaked point back to a public key, refusing the identity.
  ///
  /// # Errors
  ///
  /// Returns `InvalidTweak` when the point is at infinity, which is no key;
  /// the tweak cancelled the public key it was applied to.
  fn tweaked_g1_to_pk(point: G1) -> Result<Self::InnerPk, BlsError> {
    if point.is_inf() {
      return Err(BlsError::InvalidTweak);
    }
    Self::g1_to_pk(point)
  }

  /// Verify an aggregate signature where every signer signed `msg`.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `VerifyFailed`
  /// when the aggregate does not verify.
  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: Self::Msg<'_>, pks: &[&Self::InnerPk]) -> Result<(), BlsError>;

  /// Verify an aggregate carrying one message per signer.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the message and key counts differ,
  /// `EmptyAggregation` when no keys are given, `DuplicateMessage` where the
  /// scheme refuses a repeat, or `VerifyFailed` on mismatch.
  fn verify_aggregates(sig: &Self::InnerSig, msgs: &[Self::Msg<'_>], pks: &[&Self::InnerPk]) -> Result<(), BlsError>;

  /// Decode a sorted input public key from its 48-byte encoding to a G1 point
  /// for secure aggregation.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the bytes do not decode to a point.
  fn secure_agg_point(pk_bytes: &[u8; 48]) -> Result<G1, BlsError>;

  /// Aggregate public keys with the weighting that resists rogue keys.
  ///
  /// Each key is weighted by `SHA256(index || SHA256(sorted pk bytes))` so a
  /// signer cannot cancel an honest key with a crafted rogue one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `InvalidPublicKey`
  /// when a key or the weighted sum fails to decode.
  fn secure_aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    // Sort by serialized key so the weighting order is deterministic and
    // independent of the order the caller supplied.
    let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| Self::pk_to_bytes(pk)).collect();
    sorted.sort_unstable();

    let mut acc = G1::identity();
    for (pk_bytes, weight) in sorted.iter().zip(secure_weights(&sorted)) {
      acc += Self::secure_agg_point(pk_bytes)?.mul_scalar(&weight.b, WEIGHT_BITS);
    }

    Self::g1_to_pk(acc)
  }

  /// Verify an aggregate against the weighted key
  /// [`Self::secure_aggregate_pk`] builds, in the scheme's own single
  /// pairing.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, `InvalidPublicKey`
  /// when a key fails to decode, or `VerifyFailed` on mismatch.
  fn secure_verify_aggregates(
    sig: &Self::InnerSig,
    msg: Self::Msg<'_>,
    pks: &[&Self::InnerPk],
  ) -> Result<(), BlsError> {
    Self::verify(sig, msg, &Self::secure_aggregate_pk(pks)?)
  }

  /// Aggregate signatures under the same public-key weighting that
  /// [`Self::secure_verify_aggregates`] checks.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the signature and key counts differ,
  /// `EmptyAggregation` when nothing is given, or `InvalidSignature` when a
  /// signature or the weighted sum fails to decode.
  fn secure_aggregate_sig(sigs: &[&Self::InnerSig], pks: &[&Self::InnerPk]) -> Result<Self::InnerSig, BlsError> {
    if sigs.len() != pks.len() {
      return Err(BlsError::CountMismatch);
    }
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    // Each signature takes the weight of its own key, so the pairs travel
    // together through the same sort the verifying side applies.
    let mut paired: Vec<([u8; 48], &Self::InnerSig)> = pks
      .iter()
      .zip(sigs)
      .map(|(pk, sig)| (Self::pk_to_bytes(pk), *sig))
      .collect();
    paired.sort_by_key(|(pk_bytes, _)| *pk_bytes);

    let sorted: Vec<[u8; 48]> = paired.iter().map(|(pk_bytes, _)| *pk_bytes).collect();

    let mut acc = G2::identity();
    for ((_, sig), weight) in paired.iter().zip(secure_weights(&sorted)) {
      acc += Self::sig_to_g2(sig)?.mul_scalar(&weight.b, WEIGHT_BITS);
    }

    Self::g2_to_sig(acc)
  }

  /// Sum multiple secret keys (mod group order).
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or
  /// `InvalidSecretKey` when the sum is not a valid scalar.
  fn aggregate_sk(sks: &[&Self::InnerSk]) -> Result<Self::InnerSk, BlsError> {
    if sks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let out_bytes = sum_sk_scalars(sks.iter().map(|k| Self::sk_to_bytes(k)));
    Self::sk_from_bytes(&out_bytes).map_err(|_| BlsError::InvalidSecretKey)
  }

  /// Split a secret key into `threshold`-of-`ids.len()` shares, handing each
  /// id and share key to `into_share` to build the caller's share type.
  ///
  /// # Errors
  ///
  /// Returns `InvalidThreshold` when `threshold < 2` (a 1-of-n split hands
  /// the master key to every participant), `ids` is empty, or `threshold >
  /// ids.len()`; `ZeroScalar`/`DuplicateShareId` on bad ids;
  /// `InvalidSecretKey` when share generation or parsing fails.
  fn split_sk<S>(
    sk: &Self::InnerSk,
    threshold: usize,
    ids: &[BlsShareId],
    rng: &mut impl rand_core::CryptoRng,
    mut into_share: impl FnMut(BlsShareId, Self::InnerSk) -> S,
  ) -> Result<Vec<S>, BlsError> {
    if threshold < 2 || ids.is_empty() || threshold > ids.len() {
      return Err(BlsError::InvalidThreshold);
    }

    // An id congruent to zero mod r would make the share equal the master
    // key, and ids congruent mod r collide during interpolation.
    let id_refs: Vec<&BlsShareId> = ids.iter().collect();
    let xs = reduce_share_ids(&id_refs)?;

    let sk_bytes = Self::sk_to_bytes(sk);
    let raw = generate_shares(&sk_bytes, threshold, ids, &xs, rng).map_err(|()| BlsError::InvalidSecretKey)?;

    raw
      .into_iter()
      .map(|share| {
        let inner = Self::sk_from_bytes(&share.secret).map_err(|_| BlsError::InvalidSecretKey)?;
        Ok(into_share(share.id, inner))
      })
      .collect()
  }

  /// Recover a full signature from threshold shares by interpolation.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientShares` when fewer than two shares are given,
  /// `CountMismatch` when `ids` and `sigs` differ in length,
  /// `ZeroScalar`/`DuplicateShareId` on bad ids, or `InvalidSignature`
  /// when a share fails to decode or the recovered point is the identity.
  fn recover_sig_shares(ids: &[&BlsShareId], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.len() < 2 {
      return Err(BlsError::InsufficientShares);
    }
    // ids and sigs are paired; a length mismatch would desync interpolation
    // and could index out of bounds in interpolate_g2.
    if ids.len() != sigs.len() {
      return Err(BlsError::CountMismatch);
    }

    // Reduce and validate ids in the scalar field, rejecting zero-reducing
    // and (post-reduction) duplicate ids.
    let reduced = reduce_share_ids(ids)?;
    let points = sigs
      .iter()
      .map(|s| Self::sig_to_g2(s))
      .collect::<Result<Vec<_>, BlsError>>()?;

    let recovered = interpolate_g2(&reduced, &points);
    if recovered.is_inf() {
      return Err(BlsError::InvalidSignature);
    }
    Self::g2_to_sig(recovered)
  }

  /// Recover a full public key from threshold shares by interpolation.
  ///
  /// The G1 counterpart of [`Self::recover_sig_shares`] the same interpolation,
  /// over the group public keys live in.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientShares` when fewer than two shares are given,
  /// `CountMismatch` when `ids` and `pks` differ in length,
  /// `ZeroScalar`/`DuplicateShareId` on bad ids, or `InvalidPublicKey`
  /// when a share fails to decode or the recovered point is the identity.
  fn recover_pk_shares(ids: &[&BlsShareId], pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.len() < 2 {
      return Err(BlsError::InsufficientShares);
    }
    // ids and pks are paired; a length mismatch would desync interpolation
    // and could index out of bounds in interpolate_g1.
    if ids.len() != pks.len() {
      return Err(BlsError::CountMismatch);
    }

    let reduced = reduce_share_ids(ids)?;
    let points = pks
      .iter()
      .map(|pk| Self::pk_to_g1(pk))
      .collect::<Result<Vec<_>, BlsError>>()?;

    let recovered = interpolate_g1(&reduced, &points);
    if recovered.is_inf() {
      return Err(BlsError::InvalidPublicKey);
    }
    Self::g1_to_pk(recovered)
  }

  /// Derive a public key share from the master verification vector.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientCoefficients` when fewer than two keys are
  /// given, `ZeroScalar` on a zero-reducing id, or `InvalidPublicKey`
  /// when a coefficient or the result fails to decode.
  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &BlsShareId) -> Result<Self::InnerPk, BlsError> {
    // Evaluating the verification-vector polynomial needs >= 2 coefficients.
    if master_pks.len() < 2 {
      return Err(BlsError::InsufficientCoefficients);
    }
    let coeffs_g1 = master_pks
      .iter()
      .map(|pk| Self::pk_to_g1(pk))
      .collect::<Result<Vec<_>, BlsError>>()?;

    let x = Fr::from_bendian_reduce(id.as_bytes())?;
    let result = eval_poly_g1(&coeffs_g1, &x);

    Self::g1_to_pk(result)
  }

  /// Evaluate the master secret polynomial at a participant id, the secret
  /// counterpart to [`Self::derive_pk_share`].
  ///
  /// The secret and public evaluations are one polynomial over different
  /// groups, which is why they share an error contract: two coefficients are
  /// the minimum that describes a polynomial, and the id reduces first.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientCoefficients` when fewer than two keys are given,
  /// `ZeroScalar` on a zero-reducing id, or `InvalidSecretKey` when the
  /// result is not a valid scalar.
  fn derive_sk_share(master_sks: &[&Self::InnerSk], id: &BlsShareId) -> Result<Self::InnerSk, BlsError> {
    if master_sks.len() < 2 {
      return Err(BlsError::InsufficientCoefficients);
    }

    let mut coeffs = Zeroizing::new(Vec::with_capacity(master_sks.len()));
    for sk in master_sks {
      let bytes = Self::sk_to_bytes(sk);
      let mut scalar = blst_ffi::scalar_from_bendian(&bytes);
      coeffs.push(Fr::from(&scalar));
      scalar.b.zeroize();
    }

    let x = Fr::from_bendian_reduce(id.as_bytes())?;
    let mut y = poly_eval(&coeffs, &x);

    let mut y_scalar = blst::blst_scalar::from(&y);
    let y_bytes = Zeroizing::new(blst_ffi::bendian_from_scalar(&y_scalar));
    y_scalar.b.zeroize();
    y.zeroize();

    Self::sk_from_bytes(&y_bytes)
  }
}

/// The scalar each key is weighted by, for key encodings in sorted order.
///
/// `SHA256(index || SHA256(all keys))`, kept in one place so the secure
/// aggregate and its verification cannot drift apart.
fn secure_weights(sorted_pks: &[[u8; 48]]) -> Vec<blst::blst_scalar> {
  let mut hasher = Sha256::new();
  for pk_bytes in sorted_pks {
    hasher.update(pk_bytes);
  }
  let pk_hash: [u8; 32] = hasher.finalize().into();

  (0..sorted_pks.len())
    .map(|i| {
      let mut weight_hasher = Sha256::new();
      // The index is represented on the hash wire as 4-byte unsigned big-endian
      weight_hasher.update((i as u32).to_be_bytes());
      weight_hasher.update(pk_hash);
      let weight_hash: [u8; 32] = weight_hasher.finalize().into();
      blst_ffi::scalar_from_bendian(&weight_hash)
    })
    .collect()
}

/// Sum secret key scalars (mod group order).
fn sum_sk_scalars(key_bytes: impl Iterator<Item = Zeroizing<[u8; 32]>>) -> Zeroizing<[u8; 32]> {
  let mut acc = Fr::default();
  for bytes in key_bytes {
    let mut scalar = blst_ffi::scalar_from_bendian(&bytes);
    let mut term = Fr::from(&scalar);
    acc += term;
    term.zeroize();
    scalar.b.zeroize();
  }
  let mut out_scalar = blst::blst_scalar::from(&acc);
  let out_bytes = Zeroizing::new(blst_ffi::bendian_from_scalar(&out_scalar));
  out_scalar.b.zeroize();
  acc.zeroize();
  out_bytes
}

/// A generated share: participant id paired with its secret scalar bytes,
/// zeroized on drop. A custom `Debug` redacts the secret scalar.
struct RawShare {
  /// Participant identifier.
  id: BlsShareId,
  /// Secret scalar bytes, zeroized on drop.
  secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for RawShare {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("RawShare")
      .field("id", &self.id)
      .field("secret", &"[redacted]")
      .finish()
  }
}

/// Generate secret key shares from a polynomial with the
/// given constant term. Returns a Vec of (id, share_bytes)
/// pairs.
fn generate_shares(
  sk_bytes: &[u8; 32],
  threshold: usize,
  ids: &[BlsShareId],
  xs: &[Fr],
  rng: &mut impl rand_core::CryptoRng,
) -> Result<Vec<RawShare>, ()> {
  let mut coeffs = Zeroizing::new(Vec::with_capacity(threshold));

  let mut sk_scalar = blst_ffi::scalar_from_bendian(sk_bytes);
  coeffs.push(Fr::from(&sk_scalar));
  sk_scalar.b.zeroize();

  for _ in 1..threshold {
    // Generate random 32-byte IKM from CSPRNG
    let mut ikm = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *ikm);
    let rand_sk = blst::min_pk::SecretKey::key_gen_v3(ikm.as_ref(), &[]).map_err(|_| ())?;
    let mut rand_bytes = rand_sk.to_bytes();
    let mut rand_scalar = blst_ffi::scalar_from_bendian(&rand_bytes);
    coeffs.push(Fr::from(&rand_scalar));
    rand_bytes.zeroize();
    rand_scalar.b.zeroize();
  }

  let mut shares = Vec::with_capacity(ids.len());
  for (id, x) in ids.iter().zip(xs) {
    let mut y = poly_eval(&coeffs, x);

    let mut y_scalar = blst::blst_scalar::from(&y);
    let y_bytes = Zeroizing::new(blst_ffi::bendian_from_scalar(&y_scalar));
    y_scalar.b.zeroize();
    y.zeroize();

    // Wrapped so unprocessed shares still zeroize if a later caller step fails.
    shares.push(RawShare {
      id: *id,
      secret: y_bytes,
    });
  }

  Ok(shares)
}

/// Evaluate a polynomial at `x`. Coefficients are in ascending order:
/// `coeffs[0] + coeffs[1]*x + ...`.
fn poly_eval(coeffs: &[Fr], x: &Fr) -> Fr {
  // Horner's method: result = c[n-1], then for each
  // i from n-2..=0: result = result*x + c[i].
  let n = coeffs.len();
  if n == 0 {
    return Fr::default();
  }
  let mut result = coeffs[n - 1];
  for i in (0..n - 1).rev() {
    result = result * *x + coeffs[i];
  }
  result
}

/// Recover a G2 point from shares via Lagrange interpolation at x=0.
///
/// `ids` and `points` must have the same length >= 1.
/// Each id must be non-zero and unique.
fn interpolate_g2(ids: &[Fr], points: &[G2]) -> G2 {
  let n = ids.len();

  // Compute Lagrange coefficients at x=0:
  //   L_i = prod_{j!=i} id_j / (id_j - id_i)
  let coeffs = compute_lagrange_coeffs(ids);

  let mut result = G2::identity();
  for i in 0..n {
    // Convert Fr coefficient to scalar for point multiplication.
    let scalar = blst::blst_scalar::from(&coeffs[i]);
    result += points[i].mul_scalar(&scalar.b, FR_BITS);
  }
  result
}

/// Recover a G1 point from shares via Lagrange interpolation at x=0.
///
/// The G1 counterpart of [`interpolate_g2`], over the group public keys
/// live in. Same coefficients, different group.
fn interpolate_g1(ids: &[Fr], points: &[G1]) -> G1 {
  let n = ids.len();

  // Compute Lagrange coefficients at x=0:
  //   L_i = prod_{j!=i} id_j / (id_j - id_i)
  let coeffs = compute_lagrange_coeffs(ids);

  let mut result = G1::identity();
  for i in 0..n {
    // Convert Fr coefficient to scalar for point multiplication.
    let scalar = blst::blst_scalar::from(&coeffs[i]);
    result += points[i].mul_scalar(&scalar.b, FR_BITS);
  }
  result
}

/// Lagrange coefficients at x=0 for the given evaluation points (ids).
fn compute_lagrange_coeffs(ids: &[Fr]) -> Vec<Fr> {
  let n = ids.len();
  let mut coeffs = Vec::with_capacity(n);

  for i in 0..n {
    // L_i = prod_{j!=i} ids[j] / (ids[j] - ids[i])
    let mut num = Fr::ONE;
    let mut den = Fr::ONE;

    for j in 0..n {
      if i == j {
        continue;
      }
      // num *= ids[j]
      num *= ids[j];

      // den *= (ids[j] - ids[i])
      let diff = ids[j] - ids[i];
      den *= diff;
    }

    coeffs.push(num * den.inverse());
  }
  coeffs
}

/// Evaluate a polynomial of G1 points at scalar `x`.
///
/// `coeffs_g1[0] + coeffs_g1[1]*x + coeffs_g1[2]*x^2 + ...`
/// Uses Horner's method.
fn eval_poly_g1(coeffs_g1: &[G1], x: &Fr) -> G1 {
  let n = coeffs_g1.len();
  if n == 0 {
    return G1::identity();
  }
  let x_scalar = blst::blst_scalar::from(x);
  let mut result = coeffs_g1[n - 1];
  for i in (0..n - 1).rev() {
    result = result.mul_scalar(&x_scalar.b, FR_BITS) + coeffs_g1[i];
  }
  result
}

/// Parse a tweak as a scalar below the group order.
///
/// [`Fr::from_bendian_reduce`] would fold an out-of-range tweak into the field
/// behind the caller's back, so the canonical parse is used instead and a
/// value at or above the order is refused.
///
/// # Errors
///
/// Returns `InvalidTweak` when `tweak` is not below the group order.
fn tweak_scalar(tweak: &[u8; 32]) -> Result<Zeroizing<Fr>, BlsError> {
  // A tweak can be as secret as the key it moves, such as a derivation's
  // `IL`, so every copy of it is wiped like a key's would be.
  let mut lendian = Zeroizing::new(*tweak);
  lendian.reverse();

  Fr::from_lendian(&lendian)
    .map(Zeroizing::new)
    .ok_or(BlsError::InvalidTweak)
}

/// Reduce participant ids into the scalar field, rejecting ids that
/// reduce to zero and duplicates after reduction.
///
/// Two distinct hashes congruent mod `r` share a scalar, producing a
/// zero Lagrange denominator that blst inverts to zero silently; a
/// raw-byte duplicate check would not catch them.
fn reduce_share_ids(ids: &[&BlsShareId]) -> Result<Vec<Fr>, BlsError> {
  let fr_ids = ids
    .iter()
    .map(|id| Fr::from_bendian_reduce(id.as_bytes()))
    .collect::<Result<Vec<Fr>, BlsError>>()?;
  let mut reduced: Vec<[u8; 32]> = fr_ids.iter().map(|fr| *fr.to_lendian()).collect();
  reduced.sort_unstable();
  for pair in reduced.windows(2) {
    if pair[0] == pair[1] {
      return Err(BlsError::DuplicateShareId);
    }
  }
  Ok(fr_ids)
}
