//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key byte bag.

use super::EcdsaPkHash;
use crate::prelude::*;

use bitcoin_hashes::{ripemd160, sha256};
use cfg_if::cfg_if;
#[cfg(feature = "codec")]
use dash_types::codec::{read_bytes, BaseCodec, DecodeError, EncodeBuf};
use dash_types::{enum_map, Hashable};
#[cfg(feature = "codec")]
use dash_types::{impl_type, type_id::TypeId, CompactSize};

use core::cmp::Ordering;
use core::fmt;

/// Raw secp256k1 public key length without hints.
pub const ECDSA_PK_LEN: usize = 64;

// secp256k1 compressed public key length with compression bit.
const ECDSA_PKCMP_LEN: usize = (ECDSA_PK_LEN / 2) + 1;

enum_map! {
  /// SEC1 public key header byte.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  pub(super) enum Sec1Byte, u8 {
    /// Compressed, even Y coordinate.
    CompEven = 0x02,
    /// Compressed, odd Y coordinate.
    CompOdd = 0x03,
    /// Uncompressed, no parity hint.
    Uncomp = 0x04,
    /// Hybrid, even Y hint (non-standard).
    HybridEven = 0x06,
    /// Hybrid, odd Y hint (non-standard).
    HybridOdd = 0x07,
  }
}

impl Sec1Byte {
  /// Whether this prefix indicates a compressed key.
  pub const fn is_compressed(self) -> bool {
    matches!(self, Self::CompEven | Self::CompOdd)
  }

  /// Header-inclusive expected key length.
  pub const fn size(self) -> usize {
    match self {
      Self::CompEven | Self::CompOdd => ECDSA_PKCMP_LEN,
      Self::Uncomp | Self::HybridEven | Self::HybridOdd => ECDSA_PK_LEN + 1,
    }
  }
}

/// SEC-1 encoded ECDSA public key bytes.
///
/// The header byte is held as a parsed SEC1 prefix. The coordinates stay
/// unvalidated: only [`EcdsaPublicKey`](crate::ecdsa::EcdsaPublicKey) checks
/// curve membership.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct EcdsaPkBytes {
  prefix: Sec1Byte,
  buf: [u8; ECDSA_PK_LEN + 1],
}

#[cfg(feature = "codec")]
impl BaseCodec for EcdsaPkBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let n = CompactSize::decode(data)?.into_len(ECDSA_PK_LEN + 1)?;
    let raw = read_bytes(data, n)?;
    let prefix = raw
      .first()
      .and_then(|&b| Sec1Byte::try_from_base(b))
      .ok_or_else(|| DecodeError::InvalidValue {
        expected: Sec1Byte::variants().iter().map(|p| u64::from(p.to_base())).collect(),
        actual: raw.first().map_or(0, |&b| u64::from(b)),
      })?;
    if n != prefix.size() {
      return Err(DecodeError::BadLen {
        expected: vec![prefix.size()],
        actual: n,
      });
    }
    Ok(Self::new(prefix, raw))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    let bytes = self.as_bytes();
    CompactSize::from(bytes.len()).encode(buf);
    buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
  }
}

#[cfg(feature = "codec")]
impl_type!(EcdsaPkBytes);

impl Hashable for EcdsaPkBytes {
  type Hash = EcdsaPkHash;

  fn hash(&self) -> Self::Hash {
    Self::Hash::from(*ripemd160::Hash::hash(sha256::Hash::hash(self.as_bytes()).as_ref()).as_byte_array())
  }
}

impl EcdsaPkBytes {
  /// Copies `prefix.size()` bytes without validating the coordinates.
  pub(super) fn new(prefix: Sec1Byte, bytes: &[u8]) -> Self {
    debug_assert_eq!(bytes.len(), prefix.size(), "new: length disagrees with prefix");
    let mut buf = [0xFFu8; ECDSA_PK_LEN + 1];
    let len = bytes.len().min(prefix.size());
    buf[..len].copy_from_slice(&bytes[..len]);
    Self { prefix, buf }
  }

  /// The raw SEC1 bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.buf[..self.size()]
  }

  /// Returns `true` when the key is compressed.
  pub fn is_compressed(&self) -> bool {
    self.prefix.is_compressed()
  }

  /// Constructs from raw SEC1 bytes.
  pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
    let prefix = Sec1Byte::try_from_base(*bytes.first()?)?;
    if bytes.len() != prefix.size() {
      return None;
    }
    Some(Self::new(prefix, bytes))
  }

  /// Copies out the raw SEC1 bytes.
  ///
  /// Allocates, unlike the fixed-width bags; how many bytes a key occupies
  /// depends on the form it was parsed in.
  pub fn to_bytes(&self) -> Vec<u8> {
    self.as_bytes().to_vec()
  }

  /// Active byte length.
  pub fn size(&self) -> usize {
    self.prefix.size()
  }
}

impl fmt::Debug for EcdsaPkBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaPkBytes({self})")
  }
}

impl fmt::Display for EcdsaPkBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in self.as_bytes() {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}

impl Ord for EcdsaPkBytes {
  fn cmp(&self, other: &Self) -> Ordering {
    self.as_bytes().cmp(other.as_bytes())
  }
}

impl PartialOrd for EcdsaPkBytes {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use dash_types::serialize::hex as serde_hex;
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    impl ::serde::Serialize for EcdsaPkBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_hex::serialize(self.as_bytes(), serializer)
      }
    }

    impl<'de> ::serde::Deserialize<'de> for EcdsaPkBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_hex::deserialize::<_, Vec<u8>>(deserializer)?;
        Self::from_bytes(&bytes).ok_or_else(|| D::Error::custom("invalid public key"))
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{EcdsaPkBytes, Sec1Byte, ECDSA_PKCMP_LEN, ECDSA_PK_LEN};
  use crate::prelude::*;

  use hex_conservative::hex;
  use rstest::*;

  const COMPRESSED_02: [u8; ECDSA_PKCMP_LEN] =
    hex!("02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc");
  const COMPRESSED_03: [u8; ECDSA_PKCMP_LEN] =
    hex!("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

  #[rstest]
  fn compressed_roundtrip() {
    let pk = EcdsaPkBytes::from_bytes(&COMPRESSED_02).unwrap();
    assert!(pk.is_compressed());
    assert_eq!(pk.size(), ECDSA_PKCMP_LEN);
    assert_eq!(pk.as_bytes(), &COMPRESSED_02);
  }

  #[rstest]
  fn display_is_hex() {
    let pk = EcdsaPkBytes::from_bytes(&COMPRESSED_02).unwrap();
    let s = format!("{pk}");
    assert_eq!(s.len(), ECDSA_PKCMP_LEN * 2);
    assert!(s.starts_with("02"));
  }

  #[rstest]
  #[case::comp_odd(0x03, true, Sec1Byte::CompOdd, ECDSA_PKCMP_LEN)]
  #[case::hybrid_even(0x06, false, Sec1Byte::HybridEven, ECDSA_PK_LEN + 1)]
  #[case::hybrid_odd(0x07, false, Sec1Byte::HybridOdd, ECDSA_PK_LEN + 1)]
  fn from_bytes_prefix(#[case] prefix: u8, #[case] compressed: bool, #[case] expected: Sec1Byte, #[case] len: usize) {
    let buf = [prefix; ECDSA_PK_LEN + 1];
    let pk = EcdsaPkBytes::from_bytes(&buf[..len]).unwrap();
    assert_eq!(pk.is_compressed(), compressed);
    assert_eq!(pk.as_bytes()[0], expected.to_base());
    assert_eq!(pk.size(), expected.size());
  }

  #[rstest]
  #[case::bad_prefix(&[0x05; ECDSA_PK_LEN / 2])]
  #[case::wrong_length(&COMPRESSED_02[..32])]
  #[case::truncated(&[0x02u8] as &[u8])]
  fn from_bytes_rejects_invalid(#[case] input: &[u8]) {
    assert!(EcdsaPkBytes::from_bytes(input).is_none());
  }

  #[rstest]
  fn from_bytes_uncompressed() {
    let mut buf = [0x04u8; ECDSA_PK_LEN + 1];
    buf[1..33].copy_from_slice(&COMPRESSED_02[1..]);
    buf[33..].copy_from_slice(&[0xab; ECDSA_PK_LEN / 2]);
    let pk = EcdsaPkBytes::from_bytes(&buf).unwrap();
    assert!(!pk.is_compressed());
    assert_eq!(pk.size(), ECDSA_PK_LEN + 1);
    assert_eq!(pk.as_bytes(), &buf);
  }

  #[rstest]
  fn ordering_matches_bytes() {
    let a = EcdsaPkBytes::from_bytes(&COMPRESSED_02).unwrap();
    let b = EcdsaPkBytes::from_bytes(&COMPRESSED_03).unwrap();
    assert_eq!(a.cmp(&b), a.as_bytes().cmp(b.as_bytes()));
  }

  #[rstest]
  #[case(0x00)]
  #[case(0x05)]
  fn sec1_byte_rejects_invalid(#[case] byte: u8) {
    assert!(Sec1Byte::try_from_base(byte).is_none());
  }
}
