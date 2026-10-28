//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS integrated encryption scheme.

use super::error::BlsError;
use super::ies_bytes::{BlsIesBlobBytes, BlsIesMultiBytes};
use super::ies_bytes::{IV_SEED_LEN, MAX_IES_RECIPIENTS};
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::secret_ops::BlsSecretKey;
use super::BlsPkBytes;
use crate::aes_cbc::AES_BLOCK_LEN;
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::type_id::TypeId;
#[cfg(feature = "codec")]
use dash_types::{dlgt_codec, MAX_SER_SIZE};
use dash_types::{qtypestr, type_cvrt};
use hex_conservative::DisplayHex;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use core::any::type_name;
use core::array;
use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

/// Computes `SHA256(SHA256(input))`.
fn sha256d(input: &[u8]) -> [u8; IV_SEED_LEN] {
  let first = Sha256::digest(input);
  Sha256::digest(first).into()
}

/// Advances the IV chain to a recipient index. The seed is hashed once per
/// index, so index 0 is the seed itself.
pub(crate) fn iv_chain(iv_seed: &[u8; IV_SEED_LEN], index: usize) -> [u8; IV_SEED_LEN] {
  let mut chain = *iv_seed;
  for _ in 0..index {
    chain = sha256d(&chain);
  }
  chain
}

/// The leading block of a chain value, which is all the cipher takes.
pub(crate) fn iv_of(chain: &[u8; IV_SEED_LEN]) -> [u8; AES_BLOCK_LEN] {
  array::from_fn(|i| chain[i])
}

/// The initialisation vector recipient `index` decrypts under.
///
/// # Errors
///
/// Returns `IndexTooLarge` above [`MAX_IES_RECIPIENTS`].
fn iv_at_index(iv_seed: &[u8; IV_SEED_LEN], index: usize) -> Result<[u8; AES_BLOCK_LEN], BlsError> {
  if index > MAX_IES_RECIPIENTS {
    return Err(BlsError::IndexTooLarge);
  }
  Ok(iv_of(&iv_chain(iv_seed, index)))
}

/// Draws a fresh ephemeral key and IV seed.
fn ephemeral<S: BlsScheme>(rng: &mut impl CryptoRng) -> Result<(BlsSecretKey<S>, [u8; IV_SEED_LEN]), BlsError> {
  let mut ikm = Zeroizing::new([0u8; 32]);
  rng.fill_bytes(ikm.as_mut());
  let eph_sk = BlsSecretKey::<S>::from_ikm(ikm.as_ref())?;

  let mut iv_seed = [0u8; IV_SEED_LEN];
  rng.fill_bytes(&mut iv_seed);
  Ok((eph_sk, iv_seed))
}

/// A BLS-IES encrypted blob under an ephemeral key.
#[cfg_attr(
  all(feature = "codec", feature = "serde"),
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(into = "BlsIesBlobBytes", try_from = "BlsIesBlobBytes"),
  serde(bound(serialize = "", deserialize = ""))
)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct BlsIesBlob<S: BlsScheme> {
  ephemeral_pk: BlsPublicKey<S>,
  iv_seed: [u8; IV_SEED_LEN],
  data: Vec<u8>,
}

#[cfg(feature = "codec")]
dlgt_codec!(for[S: BlsScheme] BlsIesBlob<S> => BlsIesBlobBytes, Hash256, BlsError, MAX_SER_SIZE);

impl<S: BlsScheme> BlsIesBlob<S> {
  /// Constructs from an ephemeral key, an IV seed and a ciphertext.
  pub fn new(ephemeral_pk: BlsPublicKey<S>, iv_seed: [u8; IV_SEED_LEN], data: Vec<u8>) -> Self {
    Self {
      ephemeral_pk,
      iv_seed,
      data,
    }
  }

  /// Borrows the ciphertext.
  pub fn data(&self) -> &[u8] {
    &self.data
  }

  /// The ephemeral public key the sender encrypted under.
  pub fn ephemeral_pk(&self) -> &BlsPublicKey<S> {
    &self.ephemeral_pk
  }

  /// The seed the recipient's IV is derived from.
  pub fn iv_seed(&self) -> &[u8; IV_SEED_LEN] {
    &self.iv_seed
  }

  /// Re-encode the ephemeral key under another scheme.
  ///
  /// Only the ephemeral key's encoding moves; the ciphertext is untouched.
  /// The symmetric key comes from the basic encoding under both schemes, so
  /// the blob opens under either.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the target scheme refuses the ephemeral
  /// key.
  pub fn to_scheme<T: BlsScheme>(&self) -> Result<BlsIesBlob<T>, BlsError> {
    Ok(BlsIesBlob::new(
      self.ephemeral_pk.to_scheme::<T>()?,
      self.iv_seed,
      self.data.clone(),
    ))
  }
}

impl<S: BlsScheme> Clone for BlsIesBlob<S> {
  fn clone(&self) -> Self {
    Self {
      ephemeral_pk: self.ephemeral_pk,
      iv_seed: self.iv_seed,
      data: self.data.clone(),
    }
  }
}

impl<S: BlsScheme> Debug for BlsIesBlob<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, type_name::<Self>())?;
    write!(f, "(iv_seed={}, data_len={})", self.iv_seed.as_hex(), self.data.len())
  }
}

impl<S: BlsScheme> Eq for BlsIesBlob<S> {}

impl<S: BlsScheme> Hash for BlsIesBlob<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.ephemeral_pk.hash(state);
    self.iv_seed.hash(state);
    self.data.hash(state);
  }
}

impl<S: BlsScheme> PartialEq for BlsIesBlob<S> {
  fn eq(&self, other: &Self) -> bool {
    self.ephemeral_pk == other.ephemeral_pk && self.iv_seed == other.iv_seed && self.data == other.data
  }
}

type_cvrt!(for[S: BlsScheme] From<BlsIesBlob<S>> for BlsIesBlobBytes, |blob| {
  Self::new(BlsPkBytes::from(&blob.ephemeral_pk), blob.iv_seed, blob.data.clone())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsIesBlobBytes> for BlsIesBlob<S>, BlsError, |bytes| {
  Ok(Self::new(
    BlsPublicKey::from_bytes(bytes.ephemeral_pk().as_bytes())?,
    *bytes.iv_seed(),
    bytes.data().to_vec(),
  ))
});

impl BlsIesBlobBytes {
  /// Validates the ephemeral key under scheme `S`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the ephemeral key is not a valid point
  /// under `S`.
  pub fn to<S: BlsScheme>(&self) -> Result<BlsIesBlob<S>, BlsError> {
    BlsIesBlob::try_from(self)
  }
}

/// One ciphertext per recipient under an ephemeral key.
#[cfg_attr(
  all(feature = "codec", feature = "serde"),
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(into = "BlsIesMultiBytes", try_from = "BlsIesMultiBytes"),
  serde(bound(serialize = "", deserialize = ""))
)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct BlsIesMulti<S: BlsScheme> {
  ephemeral_pk: BlsPublicKey<S>,
  iv_seed: [u8; IV_SEED_LEN],
  blobs: Vec<Vec<u8>>,
}

#[cfg(feature = "codec")]
dlgt_codec!(for[S: BlsScheme] BlsIesMulti<S> => BlsIesMultiBytes, Hash256, BlsError, MAX_SER_SIZE);

impl<S: BlsScheme> BlsIesMulti<S> {
  /// Constructs from an ephemeral key, an IV seed and one ciphertext per
  /// recipient.
  ///
  /// # Errors
  ///
  /// Returns `IndexTooLarge` when there are more recipients than
  /// [`MAX_IES_RECIPIENTS`].
  pub fn new(ephemeral_pk: BlsPublicKey<S>, iv_seed: [u8; IV_SEED_LEN], blobs: Vec<Vec<u8>>) -> Result<Self, BlsError> {
    if blobs.len() > MAX_IES_RECIPIENTS {
      return Err(BlsError::IndexTooLarge);
    }

    Ok(Self {
      ephemeral_pk,
      iv_seed,
      blobs,
    })
  }

  /// Borrows the per-recipient ciphertexts.
  pub fn blobs(&self) -> &[Vec<u8>] {
    &self.blobs
  }

  /// The ephemeral public key the sender encrypted under.
  pub fn ephemeral_pk(&self) -> &BlsPublicKey<S> {
    &self.ephemeral_pk
  }

  /// The seed every recipient's IV is derived from.
  pub fn iv_seed(&self) -> &[u8; IV_SEED_LEN] {
    &self.iv_seed
  }

  /// Lift recipient `index`'s ciphertext out as a standalone blob.
  ///
  /// The seed travels with the blob, so decryption still takes the original
  /// recipient index.
  pub fn to_blob(&self, index: usize) -> Option<BlsIesBlob<S>> {
    Some(BlsIesBlob::new(
      self.ephemeral_pk,
      self.iv_seed,
      self.blobs.get(index)?.clone(),
    ))
  }

  /// Re-encode the ephemeral key under another scheme.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the target scheme refuses the ephemeral
  /// key.
  pub fn to_scheme<T: BlsScheme>(&self) -> Result<BlsIesMulti<T>, BlsError> {
    BlsIesMulti::new(self.ephemeral_pk.to_scheme::<T>()?, self.iv_seed, self.blobs.clone())
  }
}

impl<S: BlsScheme> Clone for BlsIesMulti<S> {
  fn clone(&self) -> Self {
    Self {
      ephemeral_pk: self.ephemeral_pk,
      iv_seed: self.iv_seed,
      blobs: self.blobs.clone(),
    }
  }
}

impl<S: BlsScheme> Debug for BlsIesMulti<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, type_name::<Self>())?;
    write!(
      f,
      "(iv_seed={}, blob_count={})",
      self.iv_seed.as_hex(),
      self.blobs.len()
    )
  }
}

impl<S: BlsScheme> Eq for BlsIesMulti<S> {}

impl<S: BlsScheme> Hash for BlsIesMulti<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.ephemeral_pk.hash(state);
    self.iv_seed.hash(state);
    self.blobs.hash(state);
  }
}

impl<S: BlsScheme> PartialEq for BlsIesMulti<S> {
  fn eq(&self, other: &Self) -> bool {
    self.ephemeral_pk == other.ephemeral_pk && self.iv_seed == other.iv_seed && self.blobs == other.blobs
  }
}

type_cvrt!(for[S: BlsScheme] From<BlsIesMulti<S>> for BlsIesMultiBytes, |multi| {
  Self::new(BlsPkBytes::from(&multi.ephemeral_pk), multi.iv_seed, multi.blobs.clone())
});

type_cvrt!(for[S: BlsScheme] TryFrom<BlsIesMultiBytes> for BlsIesMulti<S>, BlsError, |bytes| {
  Self::new(
    BlsPublicKey::from_bytes(bytes.ephemeral_pk().as_bytes())?,
    *bytes.iv_seed(),
    bytes.blobs().to_vec(),
  )
});

impl BlsIesMultiBytes {
  /// Validates the ephemeral key under scheme `S`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the ephemeral key is not a valid point
  /// under `S`, and `IndexTooLarge` when there are more recipients than
  /// [`MAX_IES_RECIPIENTS`].
  pub fn to<S: BlsScheme>(&self) -> Result<BlsIesMulti<S>, BlsError> {
    BlsIesMulti::try_from(self)
  }
}

impl<S: BlsScheme> BlsPublicKey<S> {
  /// Encrypt one blob for this recipient.
  ///
  /// The blob decrypts at recipient index 0. The symmetric key is the shared
  /// point's basic encoding under both schemes, as Core's is, so the blob
  /// opens under either.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` when the plaintext is empty or not a
  /// whole number of 16-byte blocks, or `InvalidPublicKey` when the shared
  /// secret cannot be derived.
  pub fn ies_encrypt(&self, plaintext: &[u8], rng: &mut impl CryptoRng) -> Result<BlsIesBlob<S>, BlsError> {
    let (eph_sk, iv_seed) = ephemeral(rng)?;
    self.ies_encrypt_with(&eph_sk, &iv_seed, plaintext)
  }

  /// Encrypt one plaintext per recipient under a single ephemeral key.
  ///
  /// Recipient `i`'s blob takes the IV at index `i` of the seed's chain. Each
  /// recipient gets its own plaintext, since a secret share is addressed to
  /// one holder alone.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` on differing plaintext and recipient counts,
  /// `IndexTooLarge` above [`MAX_IES_RECIPIENTS`] recipients,
  /// `InvalidPlaintextLength` on an empty or misaligned plaintext, and
  /// `InvalidPublicKey` when a shared secret cannot be derived.
  pub fn ies_encrypt_multi(
    recipients: &[&Self],
    plaintexts: &[&[u8]],
    rng: &mut impl CryptoRng,
  ) -> Result<BlsIesMulti<S>, BlsError> {
    let (eph_sk, iv_seed) = ephemeral(rng)?;
    Self::ies_encrypt_multi_with(&eph_sk, &iv_seed, recipients, plaintexts)
  }

  /// [`ies_encrypt`](Self::ies_encrypt) over a caller-chosen ephemeral key.
  ///
  /// # Errors
  ///
  /// As [`ies_encrypt`](Self::ies_encrypt).
  pub(crate) fn ies_encrypt_with(
    &self,
    eph_sk: &BlsSecretKey<S>,
    iv_seed: &[u8; IV_SEED_LEN],
    plaintext: &[u8],
  ) -> Result<BlsIesBlob<S>, BlsError> {
    let ciphertext = S::ies_seal(&eph_sk.0, &self.0, &iv_of(iv_seed), plaintext)?;
    Ok(BlsIesBlob::new(eph_sk.public_key(), *iv_seed, ciphertext))
  }

  /// [`ies_encrypt_multi`](Self::ies_encrypt_multi) over a caller-chosen
  /// ephemeral key.
  ///
  /// # Errors
  ///
  /// As [`ies_encrypt_multi`](Self::ies_encrypt_multi).
  pub(crate) fn ies_encrypt_multi_with(
    eph_sk: &BlsSecretKey<S>,
    iv_seed: &[u8; IV_SEED_LEN],
    recipients: &[&Self],
    plaintexts: &[&[u8]],
  ) -> Result<BlsIesMulti<S>, BlsError> {
    if plaintexts.len() != recipients.len() {
      return Err(BlsError::CountMismatch);
    }
    if recipients.len() > MAX_IES_RECIPIENTS {
      return Err(BlsError::IndexTooLarge);
    }

    let mut chain = *iv_seed;
    let mut blobs = Vec::with_capacity(recipients.len());
    for (recipient, plaintext) in recipients.iter().zip(plaintexts) {
      blobs.push(S::ies_seal(&eph_sk.0, &recipient.0, &iv_of(&chain), plaintext)?);
      chain = sha256d(&chain);
    }

    BlsIesMulti::new(eph_sk.public_key(), *iv_seed, blobs)
  }
}

impl<S: BlsScheme> BlsSecretKey<S> {
  /// Decrypt one BLS-IES blob.
  ///
  /// `index` selects the IV in the seed's chain; 0 for a standalone blob, or
  /// the original recipient index for one lifted out of a multi-recipient
  /// message.
  ///
  /// # Errors
  ///
  /// Returns `IndexTooLarge` above [`MAX_IES_RECIPIENTS`],
  /// `InvalidCiphertextLength` on an empty or misaligned ciphertext, or
  /// `InvalidPublicKey` when the shared secret cannot be derived.
  pub fn ies_decrypt(&self, blob: &BlsIesBlob<S>, index: usize) -> Result<Zeroizing<Vec<u8>>, BlsError> {
    S::ies_open(
      &self.0,
      &blob.ephemeral_pk().0,
      &iv_at_index(blob.iv_seed(), index)?,
      blob.data(),
    )
  }

  /// Decrypt one recipient's blob out of a multi-recipient message.
  ///
  /// # Errors
  ///
  /// Returns `IndexOutOfRange` when the message holds no blob at `index`,
  /// and otherwise as [`ies_decrypt`](Self::ies_decrypt).
  pub fn ies_decrypt_multi(&self, multi: &BlsIesMulti<S>, index: usize) -> Result<Zeroizing<Vec<u8>>, BlsError> {
    let ciphertext = multi.blobs().get(index).ok_or(BlsError::IndexOutOfRange)?;

    S::ies_open(
      &self.0,
      &multi.ephemeral_pk().0,
      &iv_at_index(multi.iv_seed(), index)?,
      ciphertext,
    )
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::RSEED;
  use crate::bls::{BlsScChia, BlsScIetf};

  use cfg_if::cfg_if;
  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
  use getrandom::SysRng;
  use hex_conservative::DisplayHex;
  use rand_core::UnwrapErr;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct IesVec {
    eph_sk: String,
    eph_pk: String,
    iv_seed: String,
    recipients: Vec<RecipientVec>,
  }

  #[derive(Deserialize)]
  struct RecipientVec {
    sk: String,
    pk: String,
    shared: String,
    iv: String,
    plaintext: String,
    ciphertext: String,
  }

  struct Kat<S: BlsScheme> {
    eph_sk: BlsSecretKey<S>,
    eph_pk: BlsPublicKey<S>,
    iv_seed: [u8; IV_SEED_LEN],
    recipients: Vec<RecipientVec>,
  }

  fn load_kat<S: BlsScheme>(scheme: &str) -> Kat<S> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_dh").scope(scheme);
    let v: IesVec = corpus.value("ies");

    Kat {
      eph_sk: BlsSecretKey::from_bytes(&arr_from_hex(&v.eph_sk)).unwrap(),
      eph_pk: BlsPublicKey::from_bytes(&arr_from_hex(&v.eph_pk)).unwrap(),
      iv_seed: arr_from_hex(&v.iv_seed),
      recipients: v.recipients,
    }
  }

  impl<S: BlsScheme> Kat<S> {
    /// The multi-recipient message the vectors record.
    fn message(&self) -> BlsIesMulti<S> {
      BlsIesMulti::new(
        self.eph_pk,
        self.iv_seed,
        self.recipients.iter().map(|r| vec_from_hex(&r.ciphertext)).collect(),
      )
      .unwrap()
    }
  }

  impl RecipientVec {
    fn public_key<S: BlsScheme>(&self) -> BlsPublicKey<S> {
      BlsPublicKey::from_bytes(&arr_from_hex(&self.pk)).unwrap()
    }

    fn secret_key<S: BlsScheme>(&self) -> BlsSecretKey<S> {
      BlsSecretKey::from_bytes(&arr_from_hex(&self.sk)).unwrap()
    }
  }

  fn make_sk<S: BlsScheme>(seed: usize) -> BlsSecretKey<S> {
    BlsSecretKey::from_ikm(&RSEED[seed]).unwrap()
  }

  /// The shared secret and the IV are the two inputs the ciphertext depends
  /// on, so they are pinned on their own. A mismatch in either would
  /// otherwise surface only as an unexplained ciphertext difference.
  fn assert_kat_key_material<S: BlsScheme>(scheme: &str) {
    let kat = load_kat::<S>(scheme);

    for (i, r) in kat.recipients.iter().enumerate() {
      let shared = kat.eph_sk.dh_exchange(&r.public_key::<S>()).unwrap();
      assert_eq!(shared.as_bytes().to_lower_hex_string(), r.shared);
      assert_eq!(r.secret_key::<S>().dh_exchange(&kat.eph_pk).unwrap(), shared);
      assert_eq!(iv_at_index(&kat.iv_seed, i).unwrap().to_lower_hex_string(), r.iv);
    }
  }

  #[rstest]
  #[case::chia(assert_kat_key_material::<BlsScChia>, "chia")]
  #[case::ietf(assert_kat_key_material::<BlsScIetf>, "ietf")]
  fn kat_key_material_matches_the_reference(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  /// The scheme decides how the shared point is written, but the key is
  /// its basic encoding truncated under both (Core's `ToByteVector(false)`),
  /// so the arms' DH bytes differ at the flag byte and their ciphertexts
  /// not at all.
  #[rstest]
  fn kdf_reads_the_basic_encoding() {
    let legacy_kat = load_kat::<BlsScChia>("chia");
    let basic_kat = load_kat::<BlsScIetf>("ietf");
    let legacy_r = &legacy_kat.recipients[0];
    let basic_r = &basic_kat.recipients[0];
    let plaintext = vec_from_hex(&legacy_r.plaintext);

    let legacy = legacy_kat.eph_sk.dh_exchange(&legacy_r.public_key()).unwrap();
    let basic = basic_kat.eph_sk.dh_exchange(&basic_r.public_key()).unwrap();

    assert_ne!(legacy.as_bytes()[0], basic.as_bytes()[0]);
    assert_eq!(
      legacy.as_bytes()[1..],
      basic.as_bytes()[1..],
      "one point, two encodings"
    );

    let blob = legacy_r
      .public_key::<BlsScChia>()
      .ies_encrypt_with(&legacy_kat.eph_sk, &legacy_kat.iv_seed, &plaintext)
      .unwrap();
    assert_eq!(blob.data(), vec_from_hex(&legacy_r.ciphertext));
    assert_eq!(
      vec_from_hex(&legacy_r.ciphertext),
      vec_from_hex(&basic_r.ciphertext),
      "one key under both schemes"
    );
  }

  fn assert_kat_encrypt<S: BlsScheme>(scheme: &str) {
    let kat = load_kat::<S>(scheme);
    let pks: Vec<BlsPublicKey<S>> = kat.recipients.iter().map(RecipientVec::public_key::<S>).collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let plaintexts: Vec<Vec<u8>> = kat.recipients.iter().map(|r| vec_from_hex(&r.plaintext)).collect();
    let pt_refs: Vec<&[u8]> = plaintexts.iter().map(Vec::as_slice).collect();

    let multi = BlsPublicKey::ies_encrypt_multi_with(&kat.eph_sk, &kat.iv_seed, &pk_refs, &pt_refs).unwrap();
    assert_eq!(multi, kat.message());

    // The single-recipient path is the same construction at index 0.
    let blob = pks[0]
      .ies_encrypt_with(&kat.eph_sk, &kat.iv_seed, &plaintexts[0])
      .unwrap();
    assert_eq!(blob, multi.to_blob(0).unwrap());
  }

  #[rstest]
  #[case::chia(assert_kat_encrypt::<BlsScChia>, "chia")]
  #[case::ietf(assert_kat_encrypt::<BlsScIetf>, "ietf")]
  fn kat_encrypt_matches_the_reference(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  fn assert_kat_decrypt<S: BlsScheme>(scheme: &str) {
    let kat = load_kat::<S>(scheme);
    let multi = kat.message();

    for (i, r) in kat.recipients.iter().enumerate() {
      let sk = r.secret_key::<S>();
      let plaintext = vec_from_hex(&r.plaintext);
      assert_eq!(*sk.ies_decrypt_multi(&multi, i).unwrap(), plaintext);

      // A lifted blob keeps the shared seed, so it decrypts at the index it
      // was encrypted at and at no other.
      let blob = multi.to_blob(i).unwrap();
      assert_eq!(*sk.ies_decrypt(&blob, i).unwrap(), plaintext);
    }
  }

  #[rstest]
  #[case::chia(assert_kat_decrypt::<BlsScChia>, "chia")]
  #[case::ietf(assert_kat_decrypt::<BlsScIetf>, "ietf")]
  fn kat_decrypt_matches_the_reference(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }

  fn assert_encrypt_decrypt_roundtrip<S: BlsScheme>() {
    let sk = make_sk::<S>(0);
    let plaintext = [0x42u8; 32];
    let mut rng = UnwrapErr(SysRng);

    let blob = sk.public_key().ies_encrypt(&plaintext, &mut rng).unwrap();
    assert_eq!(*sk.ies_decrypt(&blob, 0).unwrap(), plaintext);
  }

  #[rstest]
  #[case::chia(assert_encrypt_decrypt_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_encrypt_decrypt_roundtrip::<BlsScIetf>)]
  fn encrypt_decrypt_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_multi_encrypt_decrypt_roundtrip<S: BlsScheme>() {
    let sks: Vec<BlsSecretKey<S>> = (0..3).map(make_sk::<S>).collect();
    let pks: Vec<BlsPublicKey<S>> = sks.iter().map(BlsSecretKey::public_key).collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let plaintexts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 48]).collect();
    let pt_refs: Vec<&[u8]> = plaintexts.iter().map(Vec::as_slice).collect();
    let mut rng = UnwrapErr(SysRng);

    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &pt_refs, &mut rng).unwrap();
    for (i, sk) in sks.iter().enumerate() {
      assert_eq!(*sk.ies_decrypt_multi(&multi, i).unwrap(), plaintexts[i]);
      assert_eq!(*sk.ies_decrypt(&multi.to_blob(i).unwrap(), i).unwrap(), plaintexts[i]);
    }
  }

  #[rstest]
  #[case::chia(assert_multi_encrypt_decrypt_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_multi_encrypt_decrypt_roundtrip::<BlsScIetf>)]
  fn multi_encrypt_decrypt_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  /// Two recipients holding the same key still get distinct ciphertexts,
  /// because the IV advances per index rather than per key.
  #[rstest]
  fn multi_ciphertexts_differ_by_iv() {
    let sk = make_sk::<BlsScIetf>(0);
    let pk = sk.public_key();
    let plaintext = [0x77u8; 16];
    let mut rng = UnwrapErr(SysRng);

    let multi = BlsPublicKey::ies_encrypt_multi(&[&pk, &pk], &[&plaintext, &plaintext], &mut rng).unwrap();
    assert_ne!(multi.blobs()[0], multi.blobs()[1]);
  }

  #[rstest]
  fn decrypting_with_the_wrong_key_yields_junk() {
    let sk = make_sk::<BlsScIetf>(0);
    let plaintext = [0xddu8; 32];
    let mut rng = UnwrapErr(SysRng);

    let blob = sk.public_key().ies_encrypt(&plaintext, &mut rng).unwrap();
    assert_ne!(*make_sk::<BlsScIetf>(1).ies_decrypt(&blob, 0).unwrap(), plaintext);
  }

  /// Decrypting at the wrong index picks the wrong IV, which corrupts the
  /// first block and leaves the rest intact, so the check has to be on the
  /// whole plaintext.
  #[rstest]
  fn decrypting_at_the_wrong_index_yields_junk() {
    let kat = load_kat::<BlsScIetf>("ietf");
    let multi = kat.message();
    let sk = kat.recipients[1].secret_key::<BlsScIetf>();

    assert_ne!(
      *sk.ies_decrypt(&multi.to_blob(1).unwrap(), 0).unwrap(),
      vec_from_hex(&kat.recipients[1].plaintext)
    );
  }

  #[rstest]
  #[case::empty(0)]
  #[case::single(1)]
  #[case::block_and_a_half(24)]
  fn rejects_an_empty_or_unaligned_plaintext(#[case] len: usize) {
    let sk = make_sk::<BlsScIetf>(0);
    let pk = sk.public_key();
    let plaintext = vec![0xffu8; len];
    let mut rng = UnwrapErr(SysRng);

    assert_eq!(
      pk.ies_encrypt(&plaintext, &mut rng).unwrap_err(),
      BlsError::InvalidPlaintextLength
    );
    assert_eq!(
      BlsPublicKey::ies_encrypt_multi(&[&pk], &[plaintext.as_slice()], &mut rng).unwrap_err(),
      BlsError::InvalidPlaintextLength
    );
  }

  #[rstest]
  fn a_misaligned_ciphertext_survives_construction_and_decode() {
    let kat = load_kat::<BlsScIetf>("ietf");
    let misaligned = vec![0u8; 17];

    let blob = BlsIesBlob::new(kat.eph_pk, kat.iv_seed, misaligned.clone());
    assert_eq!(blob.data(), misaligned);
    assert!(BlsIesMulti::new(kat.eph_pk, kat.iv_seed, vec![misaligned.clone()]).is_ok());

    let bag = BlsIesBlobBytes::new(BlsPkBytes::from(&kat.eph_pk), kat.iv_seed, misaligned.clone());
    assert_eq!(BlsIesBlob::<BlsScIetf>::try_from(&bag).unwrap().data(), misaligned);
    assert!(BlsIesBlob::<BlsScIetf>::decode(&mut bag.to_bytes().as_slice()).is_ok());

    assert_eq!(
      kat.recipients[0]
        .secret_key::<BlsScIetf>()
        .ies_decrypt(&blob, 0)
        .unwrap_err(),
      BlsError::InvalidCiphertextLength
    );
  }

  /// A bound this crate adds, so it must sit far above any real quorum.
  #[rstest]
  fn bounds_the_iv_walk_above_any_real_quorum() {
    let kat = load_kat::<BlsScIetf>("ietf");
    let sk = kat.recipients[0].secret_key::<BlsScIetf>();
    let blob = kat.message().to_blob(0).unwrap();

    assert!(sk.ies_decrypt(&blob, MAX_IES_RECIPIENTS).is_ok());
    assert_eq!(
      sk.ies_decrypt(&blob, MAX_IES_RECIPIENTS + 1).unwrap_err(),
      BlsError::IndexTooLarge
    );
  }

  /// The chain advances once per index, so index 0 is the seed itself and
  /// every step after it is one double SHA256 further along.
  #[rstest]
  fn iv_chain_advances_once_per_index() {
    let seed = [0xcd; IV_SEED_LEN];

    assert_eq!(iv_chain(&seed, 0), seed);
    assert_eq!(iv_chain(&seed, 1), sha256d(&seed));
    assert_eq!(iv_chain(&seed, 2), sha256d(&iv_chain(&seed, 1)));
  }

  /// The cipher sees the leading block of the chain value and no more.
  #[rstest]
  fn iv_is_the_leading_block_of_the_chain() {
    let seed = [0xcd; IV_SEED_LEN];

    for index in 0..3 {
      assert_eq!(
        iv_at_index(&seed, index).unwrap(),
        iv_chain(&seed, index)[..AES_BLOCK_LEN]
      );
    }
  }

  /// Carrying the chain forward per recipient must land on the same IVs as
  /// walking to each index from the seed, or the two paths would disagree.
  #[rstest]
  fn advancing_the_chain_matches_indexed_lookup() {
    let seed = [0xcd; IV_SEED_LEN];
    let mut chain = seed;

    for index in 0..5 {
      assert_eq!(iv_of(&chain), iv_at_index(&seed, index).unwrap());
      chain = sha256d(&chain);
    }
  }

  #[rstest]
  fn rejects_mismatched_recipient_count() {
    let pk = make_sk::<BlsScIetf>(0).public_key();
    let plaintext = [0u8; 16];
    let mut rng = UnwrapErr(SysRng);

    assert_eq!(
      BlsPublicKey::ies_encrypt_multi(&[&pk, &pk], &[&plaintext[..]], &mut rng).unwrap_err(),
      BlsError::CountMismatch
    );
  }

  #[rstest]
  fn rejects_index_past_the_last_recipient() {
    let sk = make_sk::<BlsScIetf>(0);
    let plaintext = [0u8; 16];
    let mut rng = UnwrapErr(SysRng);

    let multi = BlsPublicKey::ies_encrypt_multi(&[&sk.public_key()], &[&plaintext[..]], &mut rng).unwrap();
    assert_eq!(sk.ies_decrypt_multi(&multi, 1).unwrap_err(), BlsError::IndexOutOfRange);
    assert!(multi.to_blob(1).is_none());
  }

  cfg_if! {
    if #[cfg(feature = "codec")] {
      use dash_types::codec::BaseCodec;

      /// The wire image belongs to the bag, so the operational type reaches
      /// it by conversion and decodes from the bytes it wrote.
      fn assert_codec_delegates_to_the_bag<S: BlsScheme>(scheme: &str) {
        let multi = load_kat::<S>(scheme).message();
        let blob = multi.to_blob(0).unwrap();

        let mut encoded = Vec::new();
        blob.encode(&mut encoded);
        assert_eq!(encoded, BlsIesBlobBytes::from(&blob).to_bytes());
        assert_eq!(BlsIesBlob::<S>::decode(&mut encoded.as_slice()).unwrap(), blob);

        let mut encoded = Vec::new();
        multi.encode(&mut encoded);
        assert_eq!(encoded, BlsIesMultiBytes::from(&multi).to_bytes());
        assert_eq!(BlsIesMulti::<S>::decode(&mut encoded.as_slice()).unwrap(), multi);
      }

      #[rstest]
      #[case::chia(assert_codec_delegates_to_the_bag::<BlsScChia>, "chia")]
      #[case::ietf(assert_codec_delegates_to_the_bag::<BlsScIetf>, "ietf")]
      fn codec_delegates_to_the_bag(#[case] assertion: fn(&str), #[case] scheme: &str) {
        assertion(scheme);
      }

      /// A bag carrying an ephemeral key no point decodes to has no operational
      /// counterpart, so the conversion is where that is caught.
      #[rstest]
      fn decoding_rejects_an_invalid_ephemeral_key() {
        let bag =
          BlsIesBlobBytes::new(BlsPkBytes::from_bytes([0xab; 48]), [0xcd; IV_SEED_LEN], vec![0x11; 16]);

        assert_eq!(
          BlsIesBlob::<BlsScIetf>::try_from(&bag).unwrap_err(),
          BlsError::InvalidPublicKey
        );
        assert!(BlsIesBlob::<BlsScIetf>::decode(&mut bag.to_bytes().as_slice()).is_err());
      }

      /// The bag's tag and the cipher's scheme are separate.
      ///
      /// The tag says how the ephemeral key is written and the symmetric key
      /// is the basic encoding under both, so a legacy-tagged message opens
      /// converted back or under the legacy arm directly.
      #[rstest]
      fn legacy_tagged_blob_converts_and_decrypts() {
        let kat = load_kat::<BlsScIetf>("ietf");
        let multi = kat.message();

        let legacy = multi.to_scheme::<BlsScChia>().unwrap();
        assert_ne!(
          BlsIesMultiBytes::from(&legacy).to_bytes(),
          BlsIesMultiBytes::from(&multi).to_bytes(),
          "the encoding moved"
        );
        assert_eq!(legacy.to_scheme::<BlsScIetf>().unwrap(), multi);

        // The recipient's own key is typed to the scheme it was read under, and
        // reaches the cipher the same way.
        let sk = kat.recipients[0]
          .secret_key::<BlsScIetf>()
          .to_scheme::<BlsScChia>()
          .unwrap();
        let recovered = sk
          .to_scheme::<BlsScIetf>()
          .unwrap()
          .ies_decrypt_multi(&legacy.to_scheme::<BlsScIetf>().unwrap(), 0)
          .unwrap();

        assert_eq!(*recovered, vec_from_hex(&kat.recipients[0].plaintext));
        assert_eq!(*sk.ies_decrypt_multi(&legacy, 0).unwrap(), *recovered);
      }

      cfg_if! {
        if #[cfg(feature = "serde")] {
          use dash_dev::assert_json_rt;

          #[rstest]
          fn serde_roundtrips() {
            let multi = load_kat::<BlsScIetf>("ietf").message();
            assert_json_rt(&multi.to_blob(0).unwrap());
            assert_json_rt(&multi);
          }
        }
      }
    }
  }
}
