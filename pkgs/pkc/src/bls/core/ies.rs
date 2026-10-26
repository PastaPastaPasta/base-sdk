//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's multi-recipient BLS-IES over its wrapper objects
//! (`bls/bls_ies.{h,cpp}`).
//!
//! Unlike the typed BLS-IES API, these follow Core's code: no recipient cap,
//! an empty plaintext encrypts and decrypts to an empty blob, a failed
//! encryption leaves Core's partial container, and decryption does not test
//! the blob's `IsValid`.

use super::{ies_key, make_new_key, public_key, BlsPkValue, BlsSkValue};
use crate::aes_cbc;
use crate::bls::ies_bytes::IV_SEED_LEN;
use crate::bls::ies_ops::{iv_chain, iv_of};
use crate::bls::{BlsEager, BlsSchemeKind, BlsSchemeSource, BLS_SK_LEN};
use crate::prelude::*;

#[cfg(feature = "codec")]
use super::super::BLS_PK_LEN;
#[cfg(feature = "codec")]
use dash_types::codec::{read_bytes, take, BaseCodec, DecodeError};
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
#[cfg(feature = "codec")]
use dash_types::CompactSize;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// `CBLSIESMultiRecipientBlobs`: an ephemeral key, an IV seed and one blob
/// per recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsIesMultiBlobs {
  /// The ephemeral public key.
  pub ephemeral: BlsPkValue,
  /// The seed of the IV chain.
  pub iv_seed: [u8; IV_SEED_LEN],
  /// The ciphertext for each recipient, in recipient order.
  pub blobs: Vec<Vec<u8>>,
}

/// `CBLSIESEncryptedBlob`: one recipient's blob with the ephemeral key and IV
/// seed it decrypts under.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsIesBlobValue {
  /// The ephemeral public key.
  pub ephemeral: BlsPkValue,
  /// The seed of the IV chain.
  pub iv_seed: [u8; IV_SEED_LEN],
  /// The ciphertext.
  pub data: Vec<u8>,
}

/// `CBLSIESEncryptedBlob::Decrypt`'s cipher step for `idx`: the IES key, the
/// IV chain at `idx`, then unpadded AES-256-CBC. `IsValid` is not tested.
fn decrypt_blob(
  ephemeral: &BlsPkValue,
  iv_seed: &[u8; IV_SEED_LEN],
  idx: usize,
  sk: &BlsSkValue,
  data: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
  let key = ies_key(sk, ephemeral)?;
  aes_cbc::decrypt(&key, &iv_of(&iv_chain(iv_seed, idx)), data)
}

/// `CBLSIESEncryptedObject<CBLSSecretKey>::Decrypt`'s parse: the first 32
/// plaintext bytes read as Core's `Unserialize` reads a secret key under
/// `flag`, the opposite scheme's fallback included; later bytes are ignored.
/// The key can be invalid: all-zero bytes, or `r` under the legacy flag.
fn parse_secret_key(plaintext: &[u8], flag: BlsSchemeKind) -> Option<BlsSkValue> {
  let bytes: &[u8; BLS_SK_LEN] = plaintext.get(..BLS_SK_LEN)?.try_into().ok()?;
  BlsEager::decode(bytes, BlsSchemeSource::Version(flag))
    .ok()
    .map(BlsEager::into_value)
}

impl BlsIesMultiBlobs {
  /// `InitEncrypt` with a caller's ephemeral key and IV seed, then `Encrypt`
  /// for each recipient in order until one fails, as Core's callers do
  /// (`active/dkgsession.cpp:83-95`).
  ///
  /// The flag is `true` when every recipient's blob was encrypted. A failing
  /// recipient's blob is empty when its key is invalid and zero-filled when
  /// the plaintext is not a whole number of blocks; every later blob is
  /// empty. An empty plaintext encrypts to an empty blob.
  pub fn encrypt_with(
    ephemeral_sk: &BlsSkValue,
    iv_seed: &[u8; IV_SEED_LEN],
    recipients: &[(&BlsPkValue, &[u8])],
  ) -> (Self, bool) {
    let mut out = Self {
      ephemeral: public_key(ephemeral_sk),
      iv_seed: *iv_seed,
      blobs: vec![Vec::new(); recipients.len()],
    };
    let mut chain = *iv_seed;
    for ((pk, plaintext), blob) in recipients.iter().zip(&mut out.blobs) {
      let Some(key) = ies_key(ephemeral_sk, pk) else {
        return (out, false);
      };
      if let Some(ciphertext) = aes_cbc::encrypt(&key, &iv_of(&chain), plaintext) {
        *blob = ciphertext;
      } else {
        *blob = vec![0; plaintext.len()];
        return (out, false);
      }
      chain = iv_chain(&chain, 1);
    }
    (out, true)
  }

  /// [`encrypt_with`](Self::encrypt_with) under a fresh ephemeral key and IV
  /// seed, drawn as `InitEncrypt` draws them: `MakeNewKey` takes 32 random
  /// bytes modulo `r` until they are not zero.
  pub fn encrypt(recipients: &[(&BlsPkValue, &[u8])], rng: &mut impl CryptoRng) -> (Self, bool) {
    let ephemeral_sk = make_new_key(rng);
    let mut iv_seed = [0u8; IV_SEED_LEN];
    rng.fill_bytes(&mut iv_seed);
    Self::encrypt_with(&ephemeral_sk, &iv_seed, recipients)
  }

  /// `Decrypt(idx, sk, out)`: `None` when there is no blob at `idx` or `sk`
  /// is invalid, or the blob is not a whole number of blocks.
  pub fn decrypt(&self, idx: usize, sk: &BlsSkValue) -> Option<Zeroizing<Vec<u8>>> {
    let data = self.blobs.get(idx)?;
    decrypt_blob(&self.ephemeral, &self.iv_seed, idx, sk, data)
  }

  /// `CBLSIESMultiRecipientObjects<CBLSSecretKey>::Decrypt`: the blob at
  /// `idx` decrypted and parsed as a secret key under `flag`.
  pub fn decrypt_secret_key(&self, idx: usize, sk: &BlsSkValue, flag: BlsSchemeKind) -> Option<BlsSkValue> {
    parse_secret_key(&self.decrypt(idx, sk)?, flag)
  }

  /// `CBLSIESMultiRecipientObjects::Get(idx)`: the blob at `idx` with the
  /// shared ephemeral key and seed.
  pub fn get(&self, idx: usize) -> Option<BlsIesBlobValue> {
    Some(BlsIesBlobValue {
      ephemeral: self.ephemeral.clone(),
      iv_seed: self.iv_seed,
      data: self.blobs.get(idx)?.clone(),
    })
  }
}

impl BlsIesBlobValue {
  /// `CBLSIESEncryptedBlob::Decrypt(idx, sk, out)`, `idx` naming the IV in
  /// the seed's chain: `None` when `sk` is invalid or the data is not a
  /// whole number of blocks.
  pub fn decrypt(&self, idx: usize, sk: &BlsSkValue) -> Option<Zeroizing<Vec<u8>>> {
    decrypt_blob(&self.ephemeral, &self.iv_seed, idx, sk, &self.data)
  }

  /// `CBLSIESEncryptedObject<CBLSSecretKey>::Decrypt(idx, sk, out)`.
  pub fn decrypt_secret_key(&self, idx: usize, sk: &BlsSkValue, flag: BlsSchemeKind) -> Option<BlsSkValue> {
    parse_secret_key(&self.decrypt(idx, sk)?, flag)
  }
}

#[cfg(feature = "codec")]
fn decode_ephemeral(data: &mut &[u8], flag: BlsSchemeKind) -> Result<BlsPkValue, DecodeError> {
  let bytes = take::<BLS_PK_LEN>(data)?;
  BlsEager::decode(&bytes, BlsSchemeSource::Version(flag))
    .map(BlsEager::into_value)
    .map_err(|_| DecodeError::MalleableBls)
}

#[cfg(feature = "codec")]
fn decode_bytes(data: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
  let len = CompactSize::decode_size(data)?.into_len(data.len())?;
  Ok(read_bytes(data, len)?.to_vec())
}

#[cfg(feature = "codec")]
impl BlsIesMultiBlobs {
  /// Core's serialization under `flag`: the ephemeral key, the seed, then
  /// the blobs as a `CompactSize` count of `CompactSize`-prefixed strings.
  pub fn to_bytes(&self, flag: BlsSchemeKind) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.ephemeral.to_bytes(flag));
    buf.extend_from_slice(&self.iv_seed);
    CompactSize::from(self.blobs.len()).encode(&mut buf);
    for blob in &self.blobs {
      CompactSize::from(blob.len()).encode(&mut buf);
      buf.extend_from_slice(blob);
    }
    buf
  }

  /// Core's `Unserialize` under `flag`, consuming what it reads: the
  /// ephemeral key decodes eagerly with the opposite scheme's fallback, and
  /// the count and each length are `ReadCompactSize`'s, capped at
  /// `MAX_SIZE` and by the input's length.
  ///
  /// # Errors
  ///
  /// Returns a [`DecodeError`] on truncated input, a non-canonical
  /// `CompactSize` or one above `MAX_SIZE`, or a key canonical in neither
  /// scheme.
  pub fn decode(data: &mut &[u8], flag: BlsSchemeKind) -> Result<Self, DecodeError> {
    let ephemeral = decode_ephemeral(data, flag)?;
    let iv_seed = take::<IV_SEED_LEN>(data)?;
    let count = CompactSize::decode_size(data)?.into_len(data.len())?;
    let mut blobs = Vec::new();
    for _ in 0..count {
      blobs.push(decode_bytes(data)?);
    }
    Ok(Self {
      ephemeral,
      iv_seed,
      blobs,
    })
  }
}

#[cfg(feature = "codec")]
impl BlsIesBlobValue {
  /// Core's serialization under `flag`: the ephemeral key, the seed and the
  /// `CompactSize`-prefixed data.
  pub fn to_bytes(&self, flag: BlsSchemeKind) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.ephemeral.to_bytes(flag));
    buf.extend_from_slice(&self.iv_seed);
    CompactSize::from(self.data.len()).encode(&mut buf);
    buf.extend_from_slice(&self.data);
    buf
  }

  /// Core's `Unserialize` under `flag`, consuming what it reads.
  ///
  /// # Errors
  ///
  /// As [`BlsIesMultiBlobs::decode`].
  pub fn decode(data: &mut &[u8], flag: BlsSchemeKind) -> Result<Self, DecodeError> {
    Ok(Self {
      ephemeral: decode_ephemeral(data, flag)?,
      iv_seed: take::<IV_SEED_LEN>(data)?,
      data: decode_bytes(data)?,
    })
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey};

  use hex_conservative::hex;
  use rstest::rstest;

  fn sk(seed: u8) -> BlsSkValue {
    let key = BlsSecretKey::<BlsScIetf>::from_ikm(&[seed; 32]).unwrap();
    BlsSkValue::from_canonical(&key.to_bytes(), BlsSchemeKind::Basic).unwrap()
  }

  fn pk(seed: u8) -> BlsPkValue {
    public_key(&sk(seed))
  }

  /// The ephemeral key is the typed API's public key for the same secret.
  #[test]
  fn ephemeral_key_is_the_public_key() {
    let typed = BlsSecretKey::<BlsScIetf>::from_ikm(&[9; 32]).unwrap().public_key();
    assert_eq!(pk(9).to_bytes(BlsSchemeKind::Basic), typed.to_bytes().as_slice());
    assert!(!public_key(&BlsSkValue::invalid()).is_valid());
  }

  /// Blobs agree with the typed API's on valid inputs, under either scheme's
  /// keys, and decrypt back.
  fn assert_typed_agreement<S: BlsScheme>(kind: BlsSchemeKind) {
    let eph = BlsSecretKey::<S>::from_ikm(&[1; 32]).unwrap();
    let recipients: Vec<BlsSecretKey<S>> = (2..5).map(|i| BlsSecretKey::<S>::from_ikm(&[i; 32]).unwrap()).collect();
    let pks: Vec<BlsPublicKey<S>> = recipients.iter().map(BlsSecretKey::public_key).collect();
    let seed = [7u8; IV_SEED_LEN];
    let plain: [&[u8]; 3] = [&[1; 32], &[2; 16], &[3; 48]];
    let typed =
      BlsPublicKey::<S>::ies_encrypt_multi_with(&eph, &seed, &pks.iter().collect::<Vec<_>>(), &plain).unwrap();

    let eph_value = BlsSkValue::from_canonical(&eph.to_bytes(), kind).unwrap();
    let pk_values: Vec<BlsPkValue> = pks
      .iter()
      .map(|p| BlsPkValue::from_canonical(&p.to_bytes(), kind).unwrap())
      .collect();
    let list: Vec<(&BlsPkValue, &[u8])> = pk_values.iter().zip(plain).collect();
    let (multi, ok) = BlsIesMultiBlobs::encrypt_with(&eph_value, &seed, &list);
    assert!(ok);
    assert_eq!(multi.blobs, typed.blobs());
    assert_eq!(multi.ephemeral.to_bytes(kind), eph.public_key().to_bytes().as_slice());
    for (i, recipient) in recipients.iter().enumerate() {
      let sk_value = BlsSkValue::from_canonical(&recipient.to_bytes(), kind).unwrap();
      assert_eq!(&multi.decrypt(i, &sk_value).unwrap()[..], plain[i]);
      assert_eq!(&multi.get(i).unwrap().decrypt(i, &sk_value).unwrap()[..], plain[i]);
    }
  }

  #[rstest]
  #[case::legacy(assert_typed_agreement::<BlsScChia>, BlsSchemeKind::Legacy)]
  #[case::basic(assert_typed_agreement::<BlsScIetf>, BlsSchemeKind::Basic)]
  fn agrees_with_the_typed_api(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// An empty plaintext encrypts and decrypts to an empty blob.
  #[test]
  fn empty_plaintext_round_trips() {
    let (multi, ok) = BlsIesMultiBlobs::encrypt_with(&sk(1), &[0; IV_SEED_LEN], &[(&pk(2), &[])]);
    assert!(ok);
    assert_eq!(multi.blobs, vec![Vec::<u8>::new()]);
    assert_eq!(multi.decrypt(0, &sk(2)).unwrap().len(), 0);
  }

  /// Core's partial container: the failing blob is empty for an invalid key
  /// and zero-filled for a misaligned plaintext, and later blobs are empty.
  #[test]
  fn failure_leaves_cores_partial_container() {
    let (a, b) = (pk(2), pk(3));
    let invalid = BlsPkValue::invalid();
    let plain = [5u8; 16];
    let (multi, ok) = BlsIesMultiBlobs::encrypt_with(
      &sk(1),
      &[1; IV_SEED_LEN],
      &[(&a, &plain), (&invalid, &plain), (&b, &plain)],
    );
    assert!(!ok);
    assert_eq!(multi.blobs[0].len(), 16);
    assert!(multi.blobs[1].is_empty() && multi.blobs[2].is_empty());

    let (multi, ok) = BlsIesMultiBlobs::encrypt_with(&sk(1), &[1; IV_SEED_LEN], &[(&a, &[5; 17]), (&b, &plain)]);
    assert!(!ok);
    assert_eq!(multi.blobs, vec![vec![0; 17], Vec::new()]);
  }

  /// Decryption needs a blob at the index, a valid key and whole blocks.
  #[test]
  fn decrypt_refusals() {
    let (multi, _) = BlsIesMultiBlobs::encrypt_with(&sk(1), &[1; IV_SEED_LEN], &[(&pk(2), &[4; 32])]);
    assert!(multi.decrypt(1, &sk(2)).is_none());
    assert!(multi.decrypt(0, &BlsSkValue::invalid()).is_none());
    let mut short = multi.get(0).unwrap();
    short.data.pop();
    assert!(short.decrypt(0, &sk(2)).is_none());
    assert_ne!(&multi.decrypt(0, &sk(3)).unwrap()[..], &[4; 32]);
  }

  /// The secret-key parse reads 32 bytes under the flag with the fallback,
  /// ignores the rest, and can give an invalid key.
  #[test]
  fn secret_key_parse() {
    let r = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let key = sk(8).to_bytes(BlsSchemeKind::Basic);
    let cases: [(Vec<u8>, BlsSchemeKind, Option<bool>); 6] = [
      ([&key[..], &[9; 16]].concat(), BlsSchemeKind::Basic, Some(true)),
      (vec![0; 32], BlsSchemeKind::Basic, Some(false)),
      (r.to_vec(), BlsSchemeKind::Basic, Some(true)),
      (r.to_vec(), BlsSchemeKind::Legacy, Some(false)),
      ([0xff; 32].to_vec(), BlsSchemeKind::Basic, None),
      (key[..31].to_vec(), BlsSchemeKind::Basic, None),
    ];
    for (plain, flag, want) in cases {
      let seed = [2; IV_SEED_LEN];
      let padded: Vec<u8> = plain
        .iter()
        .copied()
        .chain(core::iter::repeat(0))
        .take(plain.len().div_ceil(16) * 16)
        .collect();
      let (multi, ok) = BlsIesMultiBlobs::encrypt_with(&sk(1), &seed, &[(&pk(2), &padded)]);
      assert!(ok);
      let got = if plain.len() < 32 {
        parse_secret_key(&plain, flag)
      } else {
        let got = multi.decrypt_secret_key(0, &sk(2), flag);
        let blob = multi.get(0).unwrap().decrypt_secret_key(0, &sk(2), flag);
        assert_eq!(blob.map(|k| k.to_bytes(flag)), got.as_ref().map(|k| k.to_bytes(flag)));
        got
      };
      assert_eq!(got.map(|k| k.is_valid()), want, "{flag:?} {plain:02x?}");
    }
  }

  #[cfg(feature = "codec")]
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn wire_round_trip(#[case] flag: BlsSchemeKind) {
    let (multi, _) = BlsIesMultiBlobs::encrypt_with(&sk(1), &[3; IV_SEED_LEN], &[(&pk(2), &[1; 16]), (&pk(3), &[])]);
    let bytes = multi.to_bytes(flag);
    assert_eq!(bytes.len(), 48 + 32 + 1 + 17 + 1);
    let mut data = &bytes[..];
    assert_eq!(BlsIesMultiBlobs::decode(&mut data, flag).unwrap(), multi);
    assert!(data.is_empty());
    // Under the other scheme the key is the invalid object, or another point
    // where its bytes are canonical in both schemes.
    let other = BlsIesMultiBlobs::decode(&mut &bytes[..], flag.opposite()).unwrap();
    assert_ne!(other.ephemeral, multi.ephemeral);
    assert_eq!(other.blobs, multi.blobs);

    let blob = multi.get(0).unwrap();
    let bytes = blob.to_bytes(flag);
    assert_eq!(BlsIesBlobValue::decode(&mut &bytes[..], flag).unwrap(), blob);
  }

  /// A length above `MAX_SIZE` fails even with the bytes present, as
  /// `ReadCompactSize` does. The container's count is read the same way.
  #[cfg(feature = "codec")]
  #[test]
  fn lengths_above_max_size_fail() {
    const MAX_SIZE: usize = 0x0200_0000;
    let blob = BlsIesBlobValue {
      ephemeral: pk(1),
      iv_seed: [3; IV_SEED_LEN],
      data: Vec::new(),
    };
    let head = blob.to_bytes(BlsSchemeKind::Basic);
    let head = &head[..head.len() - 1];
    for len in [MAX_SIZE, MAX_SIZE + 1] {
      let mut wire = head.to_vec();
      CompactSize::from(len).encode(&mut wire);
      wire.resize(wire.len() + len, 0);
      let mut rest = wire.as_slice();
      let got = BlsIesBlobValue::decode(&mut rest, BlsSchemeKind::Basic);
      assert_eq!(got.is_ok(), len == MAX_SIZE, "{len}");
    }
  }
}
