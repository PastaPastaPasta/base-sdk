//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key.

use super::curve_consts::ERASED_POINT;
#[cfg(feature = "codec")]
use super::curve_consts::{DER_SIZES, GENERATOR, GENERATOR_COMPRESSED, OID_PRIME_FIELD, ORDER, PRIME};
use super::error::EcdsaError;
use super::public_ops::EcdsaPublicKey;
use super::secret_bytes::{EcdsaSkBytes, ECDSA_SK_LEN};
use super::sig_ops::EcdsaSignature;
use super::sig_rec_ops::EcdsaRecSignature;
use super::Compression;

#[cfg(feature = "codec")]
use bitcoin_hashes::sha256d;
#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::codec::{ensure, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::{impl_stype, type_id::TypeId, ArrayBuf};
#[cfg(feature = "codec")]
use dash_types::{Hashable, Numeric};
use rand_core::CryptoRng;
use secp256k1::ecdsa::{sign_low_r, RecoverableSignature};
use secp256k1::{Message, PublicKey, Scalar, SecretKey};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt;

#[cfg(feature = "codec")]
/// Emit a DER header followed by `bytes`.
fn der_bytes(buf: &mut impl EncodeBuf, tag: u8, bytes: &[u8]) {
  der_header(buf, tag, bytes.len());
  buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
}

#[cfg(feature = "codec")]
/// Emit a DER tag and its short, one-byte, or two-byte length.
fn der_header(buf: &mut impl EncodeBuf, tag: u8, len: usize) {
  debug_assert!(len <= u16::MAX as usize, "der_header: length exceeds u16");
  let [hi, lo] = (len as u16).to_be_bytes();
  match len {
    0..=0x7f => buf.extend_from_slice(&[tag, lo]), // nosemgrep: codec-no-raw-extend
    0x80..=0xff => buf.extend_from_slice(&[tag, 0x81, lo]), // nosemgrep: codec-no-raw-extend
    _ => buf.extend_from_slice(&[tag, 0x82, hi, lo]), // nosemgrep: codec-no-raw-extend
  }
}

#[cfg(feature = "codec")]
/// Emit a DER INTEGER, prefixing a zero byte when the high bit is set.
fn der_uint(buf: &mut impl EncodeBuf, bytes: &[u8]) {
  debug_assert!(!bytes.is_empty(), "der_uint: empty input");
  der_header(buf, 2, bytes.len() + usize::from(bytes[0] >= 0x80));
  if bytes[0] >= 0x80 {
    buf.push(0);
  }
  buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
}

/// A secp256k1 secret key.
#[derive(Clone)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct EcdsaSecretKey {
  inner: SecretKey,
  public: PublicKey,
  compressed: bool,
}

#[cfg(feature = "codec")]
impl BaseCodec<EcdsaError> for EcdsaSecretKey {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError<EcdsaError>> {
    ensure(data, 4).map_err(|e| e.lift())?;
    if data[0] != 0x30 {
      return Err(DecodeError::DecError(EcdsaError::MalformedDer));
    }
    let (len, off) = match data[1] {
      0x81 => (usize::from(data[2]) + 3, 3),
      0x82 => ((usize::from(data[2]) << 8 | usize::from(data[3])) + 4, 4),
      _ => return Err(DecodeError::DecError(EcdsaError::MalformedDer)),
    };
    let compressed = len == DER_SIZES[0];
    if !DER_SIZES.contains(&len) {
      return Err(DecodeError::BadLen {
        expected: DER_SIZES.to_vec(),
        actual: len,
      });
    }
    if data.len() < len {
      return Err(DecodeError::Eof {
        needed: len,
        remaining: data.len(),
      });
    }
    if data[off..off + 5] != [2, 1, 1, 4, 32] {
      return Err(DecodeError::DecError(EcdsaError::MalformedDer));
    }
    let mut key = Zeroizing::new([0; ECDSA_SK_LEN]);
    key.copy_from_slice(&data[off + 5..off + 5 + ECDSA_SK_LEN]);
    let candidate = Self::from_bytes(&key, Compression::from(compressed)).map_err(DecodeError::DecError)?;

    // The curve OID, field prime, generator, order, and embedded public key are
    // never read back individually; instead the scalar is re-encoded and
    // compared byte-for-byte, so any tampering anywhere in the structure,
    // including a public key that does not match the scalar, gets rejected.
    let mut expected = Zeroizing::new(ArrayBuf::<{ DER_SIZES[1] }>::new());
    candidate.encode(&mut *expected);
    if !bool::from(expected.as_bytes().ct_eq(&data[..len])) {
      return Err(DecodeError::DecError(EcdsaError::MalformedDer));
    }

    *data = &data[len..];
    Ok(candidate)
  }

  /// Encodes this key's raw scalar into `buf` as DER.
  ///
  /// `buf` receives the secret scalar in plain bytes and is not zeroized by
  /// this function; callers who need the encoded form not to outlive its use
  /// must supply a zeroizing buffer (e.g. [`ArrayBuf`](dash_types::ArrayBuf))
  /// and zeroize or drop it themselves once done.
  fn encode(&self, buf: &mut impl EncodeBuf) {
    let scalar = self.to_bytes();
    let compressed = self.public.serialize();
    let uncompressed = self.public.serialize_uncompressed();
    let public: &[u8] = if self.compressed { &compressed } else { &uncompressed };
    let generator: &[u8] = if self.compressed {
      &GENERATOR_COMPRESSED
    } else {
      GENERATOR
    };
    let point_len = public.len();
    let params_len = point_len + 97;

    der_header(buf, 0x30, 2 * point_len + 145);
    der_uint(buf, &[1]);
    der_bytes(buf, 4, &*scalar);
    der_header(buf, 0xa0, params_len + 3);
    der_header(buf, 0x30, params_len);
    der_uint(buf, &[1]);
    der_header(buf, 0x30, 44);
    der_bytes(buf, 6, OID_PRIME_FIELD);
    der_uint(buf, PRIME);
    der_header(buf, 0x30, 6);
    der_bytes(buf, 4, &[0]);
    der_bytes(buf, 4, &[7]);
    der_bytes(buf, 4, generator);
    der_uint(buf, ORDER);
    der_uint(buf, &[1]);
    der_header(buf, 0xa1, point_len + 3);
    der_header(buf, 3, point_len + 1);
    buf.push(0);
    buf.extend_from_slice(public); // nosemgrep: codec-no-raw-extend
  }
}

#[cfg(feature = "codec")]
impl_stype!(EcdsaSecretKey, DER_SIZES[1], EcdsaError);

#[cfg(feature = "codec")]
impl Hashable for EcdsaSecretKey {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    let mut buf = Zeroizing::new(ArrayBuf::<{ DER_SIZES[1] }>::new());
    self.encode(&mut *buf);
    Hash256::from_lendian(sha256d::Hash::hash(buf.as_bytes()).to_byte_array())
  }
}

/// Parse a tweak as a scalar below the curve order.
///
/// Shared with the point tweaks, which bound a tweak the same way; the parse
/// is canonical, so a value at or above the order is refused rather than
/// reduced into range behind the caller's back.
///
/// A tweak and the child key it yields give back the parent key, so callers
/// erase the scalar once it is applied.
///
/// # Errors
///
/// Returns [`EcdsaError::InvalidTweak`] when `tweak` is not below the order.
pub(super) fn tweak_scalar(tweak: &[u8; ECDSA_SK_LEN]) -> Result<Scalar, EcdsaError> {
  Scalar::from_be_bytes(*tweak).map_err(|_| EcdsaError::InvalidTweak)
}

impl EcdsaSecretKey {
  /// Parse a secret key from a 32-byte big-endian scalar.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSecretKey`] when the scalar is zero or not
  /// below the curve order.
  pub fn from_bytes(bytes: &[u8; 32], compressed: Compression) -> Result<Self, EcdsaError> {
    let mut key = SecretKey::from_secret_bytes(*bytes).map_err(|_| EcdsaError::InvalidSecretKey)?;
    let out = Self::from_inner(key, compressed);
    key.non_secure_erase();
    Ok(out)
  }

  /// Generate a new random secret key.
  ///
  /// Draws until the bytes land in `1..order`, which all but always happens
  /// on the first draw; the order leaves under 2^-127 of the 32-byte range
  /// out.
  pub fn generate(rng: &mut impl CryptoRng, compressed: Compression) -> Self {
    loop {
      let mut bytes = Zeroizing::new([0u8; ECDSA_SK_LEN]);
      rng.fill_bytes(&mut *bytes);

      if let Ok(mut key) = SecretKey::from_secret_bytes(*bytes) {
        let out = Self::from_inner(key, compressed);
        key.non_secure_erase();
        return out;
      }
    }
  }

  /// Pair a scalar with the public key it derives.
  fn from_inner(mut inner: SecretKey, compressed: Compression) -> Self {
    let key = Self {
      public: inner.public_key(),
      inner,
      compressed: compressed.is_compressed(),
    };
    // `SecretKey` is `Copy`, so the key takes a copy and `inner` stays behind.
    inner.non_secure_erase();
    key
  }

  /// Whether the corresponding public key should be compressed.
  pub fn is_compressed(&self) -> bool {
    self.compressed
  }

  /// Add `tweak` to the scalar, modulo the curve order.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidTweak`] when `tweak` is not below the curve
  /// order, or when the sum is zero. Zero is not a valid secret key, so the
  /// sum is refused rather than returned as one.
  pub fn add_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
    let mut scalar = tweak_scalar(tweak)?;
    let sum = self.inner.add_tweak(&scalar);
    scalar.non_secure_erase();
    let mut sum = sum.map_err(|_| EcdsaError::InvalidTweak)?;

    // `SecretKey` is `Copy`, so the key takes a copy and `sum` must be erased.
    let key = Self::from_inner(sum, Compression::from(self.compressed));
    sum.non_secure_erase();
    Ok(key)
  }

  /// Multiply the scalar by `tweak`, modulo the curve order.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidTweak`] when `tweak` is not below the curve
  /// order, or when it is zero. The order is prime, so no other nonzero tweak
  /// can bring the product to zero.
  pub fn mul_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
    let mut scalar = tweak_scalar(tweak)?;
    let product = self.inner.mul_tweak(&scalar);
    scalar.non_secure_erase();
    let mut product = product.map_err(|_| EcdsaError::InvalidTweak)?;

    // `SecretKey` is `Copy`, so the key takes a copy and leaves `product`.
    let key = Self::from_inner(product, Compression::from(self.compressed));
    product.non_secure_erase();
    Ok(key)
  }

  /// Negate the scalar, modulo the curve order.
  ///
  /// The stored public key is negated with it rather than rederived; mirroring
  /// the point costs nothing next to a scalar multiplication.
  ///
  /// # Errors
  ///
  /// Never returns an error.
  pub fn negate(&self) -> Result<Self, EcdsaError> {
    Ok(Self {
      inner: self.inner.negate(),
      public: self.public.negate(),
      compressed: self.compressed,
    })
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> EcdsaPublicKey {
    EcdsaPublicKey::from_inner(self.public, Compression::from(self.compressed))
  }

  /// Serialize to a 32-byte big-endian scalar.
  pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
    Zeroizing::new(self.inner.to_secret_bytes())
  }

  /// Produce an ECDSA signature over a 32-byte prehashed message (RFC 6979,
  /// low-S normalised, low-R ground).
  ///
  /// [`sign_recoverable`](Self::sign_recoverable) is not ground; its form is
  /// a fixed 64 bytes, with no prefix to save.
  pub fn sign_digest(&self, msg_hash: &[u8; 32]) -> EcdsaSignature {
    EcdsaSignature::from_inner(sign_low_r(Message::from_digest(*msg_hash), &self.inner))
  }

  /// Sign and return a recoverable signature (RFC 6979, low-S normalised).
  /// Recovery embeds the key's compression flag in the signature.
  pub fn sign_recoverable(&self, msg_hash: &[u8; 32]) -> EcdsaRecSignature {
    let rec = RecoverableSignature::sign_ecdsa_recoverable(Message::from_digest(*msg_hash), &self.inner);
    let (rid, _) = rec.serialize_compact();

    EcdsaRecSignature::from_inner(rec.to_standard(), rid, Compression::from(self.compressed))
  }

  /// Verify that a public key matches this secret key.
  ///
  /// Compares only the curve point: a caller-supplied key that serializes in a
  /// different SEC1 form than this secret key's own preference still matches if
  /// it is the same point.
  pub fn verify_pubkey(&self, pubkey: &EcdsaPublicKey) -> bool {
    &self.public == pubkey.as_inner()
  }
}

impl Zeroize for EcdsaSecretKey {
  /// Overwrites the scalar and the point it derives.
  ///
  /// The backend erases through a volatile write, which a plain assignment on
  /// the drop path would be free to elide. Zero is no scalar, so every byte is
  /// set to one instead, and the stored point follows it.
  fn zeroize(&mut self) {
    self.inner.non_secure_erase();
    // Parsing the fixed point is far cheaper than deriving it on every drop.
    self.public = PublicKey::from_byte_array_uncompressed(ERASED_POINT).unwrap_or_else(|_| self.inner.public_key());
  }
}

impl ZeroizeOnDrop for EcdsaSecretKey {}

impl Drop for EcdsaSecretKey {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl fmt::Debug for EcdsaSecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSecretKey(..)")
  }
}

impl Eq for EcdsaSecretKey {}

impl PartialEq for EcdsaSecretKey {
  fn eq(&self, other: &Self) -> bool {
    (*self.to_bytes()).ct_eq(&*other.to_bytes()).into() && self.compressed == other.compressed
  }
}

type_cvrt!(From<EcdsaSecretKey> for EcdsaSkBytes, |sk| {
  Self::from_bytes(*sk.to_bytes(), Compression::from(sk.is_compressed()))
});

type_cvrt!(TryFrom<EcdsaSkBytes> for EcdsaSecretKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes(), Compression::from(bytes.is_compressed()))
});

type_cvrt!(From<EcdsaSecretKey> for SecretKey, |sk| {
  sk.inner
});

type_cvrt!(From<SecretKey> for EcdsaSecretKey, |inner| {
  Self::from_inner(*inner, Compression::Compressed)
});

#[cfg(test)]
#[expect(clippy::ptr_arg, clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::curve_consts::{GENERATOR, GENERATOR_COMPRESSED, OID_PRIME_FIELD, ORDER};
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{Compression, EcdsaError, EcdsaPublicKey, EcdsaSecretKey, ECDSA_SK_LEN};
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  use dash_types::codec::BaseCodec;
  use rstest::*;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk_compressed: String,
  }

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
    recovery_id: u8,
  }

  #[rstest]
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn codec_roundtrip_preserves_compression(#[case] compressed: Compression) {
    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK, compressed).unwrap();
    let mut buf = Vec::new();
    sk.encode(&mut buf);
    let decoded = EcdsaSecretKey::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(*decoded.to_bytes(), *sk.to_bytes());
    assert_eq!(decoded.is_compressed(), compressed.is_compressed());
  }

  #[rstest]
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn consensus_bridge_roundtrip(#[case] compressed: Compression) {
    use bitcoin_consensus_encoding::{encode_to_vec, Decode, Decoder, DecoderStatus};

    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK, compressed).unwrap();
    let wire = encode_to_vec(&sk);

    let mut direct = Vec::new();
    sk.encode(&mut direct);
    assert_eq!(wire, direct, "bridge must match the BaseCodec image");
    assert_eq!(wire.len(), if compressed.is_compressed() { 214 } else { 279 });

    let mut dec = <EcdsaSecretKey as Decode>::decoder();
    let mut cursor = wire.as_slice();
    while matches!(dec.push_bytes(&mut cursor).unwrap(), DecoderStatus::NeedsMore) && !cursor.is_empty() {}
    let back = dec.end().unwrap();
    assert_eq!(*back.to_bytes(), *sk.to_bytes());
    assert_eq!(back.is_compressed(), compressed.is_compressed());
  }

  fn corrupt_mismatched_embedded_pubkey(buf: &mut Vec<u8>, alice: &EcdsaSecretKey, bob: &EcdsaSecretKey) {
    let point_len = alice.public_key().to_compressed().len();
    let start = buf.len() - point_len;
    buf[start..].copy_from_slice(&bob.public_key().to_compressed());
  }

  fn corrupt_tampered_curve_oid(buf: &mut Vec<u8>, _alice: &EcdsaSecretKey, _bob: &EcdsaSecretKey) {
    let pos = buf
      .windows(OID_PRIME_FIELD.len())
      .position(|w| w == OID_PRIME_FIELD)
      .unwrap();
    buf[pos] ^= 0xff;
  }

  fn corrupt_length_form_mismatch(buf: &mut Vec<u8>, _alice: &EcdsaSecretKey, _bob: &EcdsaSecretKey) {
    // Overwrite the compressed point's SEC1 prefix byte with the uncompressed
    // tag, keeping the (compressed) total length unchanged: the embedded
    // point no longer matches a re-encoding of the scalar.
    let point_start = buf.len() - 33;
    buf[point_start] = 0x04;
  }

  fn corrupt_truncated_body(buf: &mut Vec<u8>, _alice: &EcdsaSecretKey, _bob: &EcdsaSecretKey) {
    buf.truncate(buf.len() - 1);
  }

  #[rstest]
  #[case::mismatched_embedded_pubkey(corrupt_mismatched_embedded_pubkey)]
  #[case::tampered_curve_oid(corrupt_tampered_curve_oid)]
  #[case::length_form_mismatch(corrupt_length_form_mismatch)]
  #[case::truncated_body(corrupt_truncated_body)]
  fn decode_rejects_malformed_der(
    alice_sk: EcdsaSecretKey,
    bob_sk: EcdsaSecretKey,
    #[case] corrupt: fn(&mut Vec<u8>, &EcdsaSecretKey, &EcdsaSecretKey),
  ) {
    let mut buf = Vec::new();
    alice_sk.encode(&mut buf);
    corrupt(&mut buf, &alice_sk, &bob_sk);
    assert!(EcdsaSecretKey::decode(&mut buf.as_slice()).is_err());
  }

  #[rstest]
  fn corpus_derive_pk() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_keygen");
    for v in corpus.vectors::<KeygenVector>("derive_pk") {
      let sk = EcdsaSecretKey::from_bytes(&arr_from_hex(&v.sk), Compression::Compressed).unwrap();
      assert_eq!(sk.public_key().to_compressed(), arr_from_hex::<33>(&v.pk_compressed));
    }
  }

  #[rstest]
  fn corpus_sign_recoverable() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_sign");
    for v in corpus.vectors::<SignVector>("sign_recoverable") {
      let sk = EcdsaSecretKey::from_bytes(&arr_from_hex(&v.sk), Compression::Compressed).unwrap();
      let sig = sk.sign_recoverable(&arr_from_hex::<32>(&v.msg));
      assert_eq!(sig.to_compact(), arr_from_hex::<64>(&v.sig));
      assert_eq!(sig.recovery_id(), v.recovery_id);
    }
  }

  #[rstest]
  fn the_generator_constant_matches_the_library() {
    // The DER encoding names the generator, which the curve library does not
    // expose; this is the check that the written-out constant is that point.
    let one = EcdsaSecretKey::from_bytes(
      &[0u8; 31]
        .iter()
        .chain(&[1u8])
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(),
      Compression::Compressed,
    )
    .unwrap();

    assert_eq!(one.public_key().to_uncompressed(), *GENERATOR);
    assert_eq!(one.public_key().to_compressed(), GENERATOR_COMPRESSED);
  }

  /// What the backend's erase leaves in place of the scalar.
  const WIPED: [u8; ECDSA_SK_LEN] = [1u8; ECDSA_SK_LEN];

  #[rstest]
  fn zeroize_clears_the_scalar(alice_sk: EcdsaSecretKey) {
    use zeroize::Zeroize;

    let mut sk = alice_sk;
    let held = sk.public_key();
    sk.zeroize();

    // Zero is not a valid scalar, so the wiped key holds one instead; what
    // matters is that the original scalar is gone.
    assert_ne!(*sk.to_bytes(), ALICE_SK);
    assert_eq!(*sk.to_bytes(), WIPED);

    // The stored point follows the scalar, or a wiped key would go on
    // vouching for the public key it used to hold.
    assert_ne!(sk.public_key(), held);
    assert!(sk.verify_pubkey(&sk.public_key()));
    assert!(!sk.verify_pubkey(&held));

    // The stored point is a constant, so it must match the derived one.
    let erased = EcdsaSecretKey::from_bytes(&WIPED, Compression::Compressed).unwrap();
    assert_eq!(sk.public_key(), erased.public_key());
  }

  #[rstest]
  fn from_bytes_roundtrip(alice_sk: EcdsaSecretKey) {
    let bytes = alice_sk.to_bytes();
    let restored = EcdsaSecretKey::from_bytes(&bytes, Compression::Compressed).unwrap();
    assert_eq!(
      restored.public_key().to_compressed(),
      alice_sk.public_key().to_compressed()
    );
  }

  #[derive(Clone, Copy, Debug)]
  enum Tweak {
    Add,
    Mul,
    Neg,
  }

  impl Tweak {
    fn on_sk(self, sk: &EcdsaSecretKey, tweak: &[u8; ECDSA_SK_LEN]) -> EcdsaSecretKey {
      match self {
        Tweak::Add => sk.add_tweak(tweak).unwrap(),
        Tweak::Mul => sk.mul_tweak(tweak).unwrap(),
        Tweak::Neg => sk.negate().unwrap(),
      }
    }

    fn on_pk(self, pk: &EcdsaPublicKey, tweak: &[u8; ECDSA_SK_LEN]) -> EcdsaPublicKey {
      match self {
        Tweak::Add => pk.add_tweak(tweak).unwrap(),
        Tweak::Mul => pk.mul_tweak(tweak).unwrap(),
        Tweak::Neg => pk.negate().unwrap(),
      }
    }
  }

  #[rstest]
  fn tweak_agrees_on_both_sides(
    #[values(Tweak::Add, Tweak::Mul, Tweak::Neg)] op: Tweak,
    #[values(Compression::Compressed, Compression::Uncompressed)] compressed: Compression,
    bob_sk: EcdsaSecretKey,
  ) {
    // A tweak on k has to land on the matching tweak on kG, or the same tweak
    // applied to the two halves of a key pair would part them.
    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK, compressed).unwrap();
    let tweak = *bob_sk.to_bytes();
    let tweaked_sk = op.on_sk(&sk, &tweak);
    let tweaked_pk = op.on_pk(&sk.public_key(), &tweak);

    assert_eq!(tweaked_sk.public_key(), tweaked_pk);
    assert!(tweaked_sk.verify_pubkey(&tweaked_pk));
    assert_eq!(tweaked_pk.verify_digest(&MSG, tweaked_sk.sign_digest(&MSG)), Ok(()));
    assert_eq!(tweaked_sk.is_compressed(), sk.is_compressed());

    // The stored point has to match the one rederived from the new scalar.
    let rederived = EcdsaSecretKey::from_bytes(&tweaked_sk.to_bytes(), compressed).unwrap();
    assert_eq!(tweaked_sk.public_key(), rederived.public_key());
  }

  #[rstest]
  fn tweak_add_refuses_order_or_above(alice_sk: EcdsaSecretKey) {
    assert_eq!(alice_sk.add_tweak(ORDER), Err(EcdsaError::InvalidTweak));
    assert_eq!(alice_sk.add_tweak(&[0xff; ECDSA_SK_LEN]), Err(EcdsaError::InvalidTweak));
  }

  #[rstest]
  fn tweak_add_refuses_zero_sum(alice_sk: EcdsaSecretKey) {
    // order - a, so a + t == 0, which is no scalar a key can hold.
    let tweak = negate_scalar(&*alice_sk.to_bytes());

    assert_eq!(alice_sk.add_tweak(&tweak), Err(EcdsaError::InvalidTweak));
  }

  #[rstest]
  fn tweak_mul_commutes(alice_sk: EcdsaSecretKey, bob_sk: EcdsaSecretKey) {
    // at == ta, so t(aG) == a(tG).
    let product = alice_sk.mul_tweak(&bob_sk.to_bytes()).unwrap();
    let swapped = bob_sk.mul_tweak(&alice_sk.to_bytes()).unwrap();

    assert_eq!(*product.to_bytes(), *swapped.to_bytes());
    assert_eq!(
      alice_sk.public_key().mul_tweak(&bob_sk.to_bytes()).unwrap(),
      bob_sk.public_key().mul_tweak(&alice_sk.to_bytes()).unwrap()
    );
  }

  #[rstest]
  fn tweak_mul_by_one_is_identity(alice_sk: EcdsaSecretKey) {
    let mut one = [0u8; ECDSA_SK_LEN];
    one[ECDSA_SK_LEN - 1] = 1;

    assert_eq!(alice_sk.mul_tweak(&one).unwrap(), alice_sk);
    assert_eq!(alice_sk.public_key().mul_tweak(&one).unwrap(), alice_sk.public_key());
  }

  #[rstest]
  fn tweak_mul_refuses_bad_factor(alice_sk: EcdsaSecretKey) {
    let zero = [0u8; ECDSA_SK_LEN];

    assert_eq!(alice_sk.mul_tweak(&zero), Err(EcdsaError::InvalidTweak));
    assert_eq!(alice_sk.mul_tweak(ORDER), Err(EcdsaError::InvalidTweak));
    assert_eq!(alice_sk.public_key().mul_tweak(&zero), Err(EcdsaError::InvalidTweak));
    assert_eq!(alice_sk.public_key().mul_tweak(ORDER), Err(EcdsaError::InvalidTweak));
  }

  #[rstest]
  fn tweak_neg_is_order_minus_scalar(alice_sk: EcdsaSecretKey) {
    assert_eq!(
      *alice_sk.negate().unwrap().to_bytes(),
      negate_scalar(&*alice_sk.to_bytes())
    );
  }

  #[rstest]
  fn tweak_neg_twice_is_identity(alice_sk: EcdsaSecretKey) {
    let negated = alice_sk.negate().unwrap();

    assert_ne!(negated, alice_sk);
    assert_eq!(negated.negate().unwrap(), alice_sk);
    assert_eq!(
      alice_sk.public_key().negate().unwrap().negate().unwrap(),
      alice_sk.public_key()
    );
  }

  #[rstest]
  fn rejects_zero() {
    assert!(EcdsaSecretKey::from_bytes(&[0u8; 32], Compression::Compressed).is_err());
  }

  #[rstest]
  fn sign_is_deterministic(alice_sk: EcdsaSecretKey) {
    let sig1 = alice_sk.sign_digest(&MSG);
    let sig2 = alice_sk.sign_digest(&MSG);
    assert_eq!(sig1, sig2);
  }

  #[rstest]
  fn sign_grinds_r_low(alice_sk: EcdsaSecretKey) {
    // R lands low half the time on its own, so one signature proves nothing.
    for i in 0..20 {
      let sig = alice_sk.sign_digest(&message_hash(i));

      assert!(sig.to_bytes()[0] < 0x80, "R is not low for message {i}");
      assert!(
        sig.to_der().len() <= 71,
        "DER is {} bytes for message {i}",
        sig.to_der().len()
      );
    }
  }

  #[rstest]
  fn sign_recoverable_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign_recoverable(&MSG);
    let recovered = EcdsaPublicKey::recover(&MSG, &sig).unwrap();
    assert_eq!(recovered, alice_sk.public_key());
  }

  #[rstest]
  fn sign_verify_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign_digest(&MSG);
    assert!(alice_sk.public_key().verify_digest(&MSG, sig).is_ok());
  }

  #[rstest]
  fn verify_pubkey_matches(alice_sk: EcdsaSecretKey) {
    assert!(alice_sk.verify_pubkey(&alice_sk.public_key()));
  }

  #[rstest]
  fn verify_pubkey_matches_regardless_of_form(alice_sk: EcdsaSecretKey) {
    let mut uncompressed = alice_sk.public_key();
    uncompressed.decompress();
    assert!(alice_sk.verify_pubkey(&uncompressed));
  }

  #[rstest]
  fn verify_rejects_wrong_key(alice_sk: EcdsaSecretKey, bob_sk: EcdsaSecretKey) {
    assert!(!alice_sk.verify_pubkey(&bob_sk.public_key()));
    let sig = alice_sk.sign_digest(&MSG);
    assert!(bob_sk.public_key().verify_digest(&MSG, sig).is_err());
  }

  #[rstest]
  fn backend_roundtrip_keeps_scalar_and_defaults_to_compressed(alice_sk: EcdsaSecretKey) {
    let inner = secp256k1::SecretKey::from(&alice_sk);
    assert_eq!(inner.to_secret_bytes(), *alice_sk.to_bytes());

    let lifted = EcdsaSecretKey::from(inner);
    assert!(lifted.is_compressed());
    assert_eq!(lifted, alice_sk);
    assert!(lifted.verify_pubkey(&alice_sk.public_key()));
  }
}
