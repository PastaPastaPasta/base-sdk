//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key byte bag.

use super::Compression;
#[cfg(feature = "codec")]
use crate::prelude::*;

#[cfg(feature = "codec")]
use base58ck::{decode_check, Base58CkString};
use dash_types::derive_sbytes;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Raw secp256k1 secret key length.
pub const ECDSA_SK_LEN: usize = 32;

/// Raw ECDSA secret key bytes.
///
/// Carries a compression flag that decides how the derived public key
/// serializes. The bytes are unvalidated: DER needs an in-range scalar, so the
/// wire codec lives in [`EcdsaSecretKey`](crate::ecdsa::EcdsaSecretKey).
#[derive(Clone, Zeroize)]
pub struct EcdsaSkBytes {
  inner: [u8; ECDSA_SK_LEN],
  #[zeroize(skip)]
  compressed: bool,
}

impl EcdsaSkBytes {
  /// Borrow the raw inner bytes.
  pub const fn as_bytes(&self) -> &[u8; ECDSA_SK_LEN] {
    &self.inner
  }

  /// Wrap raw bytes with a compression flag.
  pub const fn from_bytes(bytes: [u8; ECDSA_SK_LEN], compressed: Compression) -> Self {
    Self {
      inner: bytes,
      compressed: compressed.is_compressed(),
    }
  }

  /// Whether the corresponding public key should be compressed.
  pub const fn is_compressed(&self) -> bool {
    self.compressed
  }

  #[cfg(feature = "codec")]
  /// Decode a wallet import format-encoded private key, returning the key
  /// and the version prefix it was encoded under.
  ///
  /// Returns `None` on a bad checksum, a length outside 33 or 34 bytes, a
  /// malformed compression flag, or an all-zero scalar. Scalars at or above the
  /// curve order still pass: range checking belongs to
  /// [`EcdsaSecretKey`](crate::ecdsa::EcdsaSecretKey).
  pub fn from_wif(s: &str) -> Option<(Self, u8)> {
    let data = Zeroizing::new(decode_check(s).ok()?);
    let compressed = match data.len() {
      33 => Compression::Uncompressed,
      34 if data[33] == 0x01 => Compression::Compressed,
      _ => return None,
    };
    let key = Zeroizing::new(<[u8; ECDSA_SK_LEN]>::try_from(&data[1..33]).ok()?);
    let sk = Self::from_bytes(*key, compressed);
    (!sk.is_null()).then_some((sk, data[0]))
  }

  /// Copy out the raw inner bytes.
  pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
    Zeroizing::new(self.inner)
  }

  #[cfg(feature = "codec")]
  /// Encode as a wallet import format string.
  ///
  /// Returns `None` for the all-zero scalar, which [`from_wif`](Self::from_wif)
  /// rejects. Scalars at or above the curve order still encode, as `from_wif`
  /// defers that range check too.
  pub fn to_wif(&self, prefix: u8) -> Option<Zeroizing<String>> {
    if self.is_null() {
      return None;
    }
    let mut buf = Zeroizing::new([0u8; 34]);
    buf[0] = prefix;
    buf[1..33].copy_from_slice(&self.inner);
    let len = if self.compressed {
      buf[33] = 0x01;
      34
    } else {
      33
    };
    let mut wif = Base58CkString::encode_unbounded(&buf[..len]);
    let out = Zeroizing::new(String::from(wif.as_str()));
    let (addr, n) = (wif.as_bytes().as_ptr().addr(), wif.len());
    let base = (&raw mut wif).cast::<u8>();
    // base58ck keeps strings this short inline, so the text sits inside `wif`.
    let off = addr
      .checked_sub(base.addr())
      .filter(|off| off + n <= size_of::<Base58CkString>());
    debug_assert!(off.is_some(), "to_wif: text left base58ck's inline buffer");
    if let Some(off) = off {
      // SAFETY: `off..off + n` lies inside `wif` and any byte keeps it valid.
      unsafe { core::slice::from_raw_parts_mut(base.add(off), n) }.zeroize();
    }
    Some(out)
  }
}

derive_sbytes!(EcdsaSkBytes, ECDSA_SK_LEN);

impl Eq for EcdsaSkBytes {}

impl PartialEq for EcdsaSkBytes {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into() && self.compressed == other.compressed
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{Compression, EcdsaSkBytes, ECDSA_SK_LEN};
  use crate::prelude::*;
  use bitcoin_hashes::sha256d;

  use rstest::*;

  #[rstest]
  fn debug_redacts_inner() {
    let sk = EcdsaSkBytes::from_bytes([0xffu8; ECDSA_SK_LEN], Compression::Compressed);
    let dbg = format!("{sk:?}");
    assert_eq!(dbg, "EcdsaSkBytes(..)");
    assert!(!dbg.contains("ff"));
  }

  #[rstest]
  fn equality() {
    let a = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], Compression::Compressed);
    let b = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], Compression::Compressed);
    let c = EcdsaSkBytes::from_bytes([2u8; ECDSA_SK_LEN], Compression::Compressed);
    let d = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], Compression::Uncompressed);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d, "same scalar but different compression");
  }

  #[rstest]
  #[case::compressed(0x42, Compression::Compressed)]
  #[case::uncompressed(0x01, Compression::Uncompressed)]
  fn roundtrip(#[case] fill: u8, #[case] compressed: Compression) {
    let bytes = [fill; ECDSA_SK_LEN];
    let sk = EcdsaSkBytes::from_bytes(bytes, compressed);
    assert_eq!(*sk.to_bytes(), bytes);
    assert_eq!(sk.as_bytes(), &bytes);
    assert_eq!(sk.is_compressed(), compressed.is_compressed());
  }

  #[rstest]
  #[case::compressed(Compression::Compressed, 0x80)]
  #[case::uncompressed(Compression::Uncompressed, 0x80)]
  #[case::other_prefix(Compression::Compressed, 0xcc)]
  fn wif_roundtrip(#[case] compressed: Compression, #[case] prefix: u8) {
    let sk = EcdsaSkBytes::from_bytes([0x11u8; ECDSA_SK_LEN], compressed);
    let wif = sk.to_wif(prefix).unwrap();
    let (restored, found) = EcdsaSkBytes::from_wif(&wif).unwrap();
    assert_eq!(restored, sk);
    assert_eq!(found, prefix, "prefix preserved");
  }

  /// The encoder must not emit a string the decoder refuses to read back.
  #[rstest]
  #[case::compressed(Compression::Compressed)]
  #[case::uncompressed(Compression::Uncompressed)]
  fn to_wif_refuses_zero_scalar(#[case] compressed: Compression) {
    let zero = EcdsaSkBytes::from_bytes([0u8; ECDSA_SK_LEN], compressed);
    assert!(zero.to_wif(0x80).is_none());
  }

  fn encode_check(data: &[u8]) -> String {
    String::from(base58ck::Base58CkString::encode_unbounded(data).as_str())
  }

  /// A well-formed WIF carrying the zero scalar, assembled by hand because
  /// `to_wif` refuses to emit one; `from_wif` must still reject it.
  fn wif_zero_key() -> String {
    let mut payload = [0u8; 34];
    payload[0] = 0x80;
    payload[33] = 0x01;
    encode_check(&payload)
  }

  fn wif_bad_checksum() -> String {
    let sk = EcdsaSkBytes::from_bytes([0x22u8; ECDSA_SK_LEN], Compression::Compressed);
    let mut wif = String::from(sk.to_wif(0x80).unwrap().as_str());
    let good = base58ck::decode_check(&wif).unwrap();
    let digest = sha256d::Hash::hash(&good).to_byte_array();
    let good_check = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    // Swapping the last digit disturbs the low bytes, where the checksum lives
    let last = wif.pop().unwrap();
    wif.push(if last == '1' { '2' } else { '1' });
    let err = base58ck::decode_check(&wif).unwrap_err();
    let (found, expected) = err.incorrect_checksum().unwrap();
    assert_eq!(expected, good_check, "payload intact");
    assert_ne!(found, expected, "checksum altered");
    wif
  }

  fn wif_wrong_length() -> String {
    encode_check(&[0x80u8; 32])
  }

  fn wif_bad_compression_byte() -> String {
    let mut payload = [0u8; 34];
    payload[0] = 0x80;
    payload[1..33].copy_from_slice(&[0x44u8; ECDSA_SK_LEN]);
    payload[33] = 0x02;
    encode_check(&payload)
  }

  #[rstest]
  #[case::zero_key(wif_zero_key())]
  #[case::bad_checksum(wif_bad_checksum())]
  #[case::wrong_length(wif_wrong_length())]
  #[case::bad_compression_byte(wif_bad_compression_byte())]
  fn wif_rejects(#[case] wif: String) {
    assert!(EcdsaSkBytes::from_wif(&wif).is_none());
  }
}
