//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 compact recoverable signature byte bag.

use super::sig_bytes::{EcdsaSigBytes, ECDSA_SIG_LEN};
use super::Compression;
#[cfg(any(feature = "codec", feature = "serde"))]
use crate::prelude::*;

use bitcoin_hashes::sha256d;
use cfg_if::cfg_if;
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::codec::{read_bytes, BaseCodec, DecodeError, EncodeBuf};
use dash_types::{enum_map, type_cvrt};
#[cfg(feature = "codec")]
use dash_types::{impl_type, type_id::TypeId, CompactSize};
use dash_types::{Hashable, Numeric};

use core::fmt;

enum_map! {
  /// Header flags for a compact recoverable ECDSA signature.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  pub(super) enum CompactFlags, u8 {
    /// Uncompressed key, recovery id 0.
    Uncompressed0 = 27,
    /// Uncompressed key, recovery id 1.
    Uncompressed1 = 28,
    /// Uncompressed key, recovery id 2.
    Uncompressed2 = 29,
    /// Uncompressed key, recovery id 3.
    Uncompressed3 = 30,
    /// Compressed key, recovery id 0.
    Compressed0 = 31,
    /// Compressed key, recovery id 1.
    Compressed1 = 32,
    /// Compressed key, recovery id 2.
    Compressed2 = 33,
    /// Compressed key, recovery id 3.
    Compressed3 = 34,
  }
}

impl CompactFlags {
  /// Whether the signing key was compressed.
  pub const fn is_compressed(self) -> bool {
    self.to_base() >= Self::Compressed0.to_base()
  }

  /// Construct from recovery id and compression flag.
  pub const fn new(recovery_id: u8, compressed: Compression) -> Option<Self> {
    if recovery_id > 3 {
      return None;
    }
    Some(Self::from_parts(recovery_id, compressed))
  }

  /// Construct from the low two bits of `recovery_id` and a compression flag.
  ///
  /// Total, unlike [`CompactFlags::new`]: the eight variants cover every
  /// combination, so a caller holding an already range-checked recovery id
  /// needs no fallible path.
  pub const fn from_parts(recovery_id: u8, compressed: Compression) -> Self {
    match (recovery_id & 3, compressed) {
      (0, Compression::Uncompressed) => Self::Uncompressed0,
      (1, Compression::Uncompressed) => Self::Uncompressed1,
      (2, Compression::Uncompressed) => Self::Uncompressed2,
      (_, Compression::Uncompressed) => Self::Uncompressed3,
      (0, Compression::Compressed) => Self::Compressed0,
      (1, Compression::Compressed) => Self::Compressed1,
      (2, Compression::Compressed) => Self::Compressed2,
      (_, Compression::Compressed) => Self::Compressed3,
    }
  }

  /// Recovery ID.
  pub const fn recovery_id(self) -> u8 {
    (self.to_base() - Self::Uncompressed0.to_base()) & 3
  }
}

/// Compact recoverable ECDSA signature bytes: one header byte carrying the
/// recovery id and compression flag, then `r || s`.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct EcdsaRecSigBytes {
  flags: CompactFlags,
  sig: EcdsaSigBytes,
}

#[cfg(feature = "codec")]
impl BaseCodec for EcdsaRecSigBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let n = CompactSize::decode(data)?.into_len(ECDSA_SIG_LEN + 1)?;
    if n != ECDSA_SIG_LEN + 1 {
      return Err(DecodeError::BadLen {
        expected: vec![ECDSA_SIG_LEN + 1],
        actual: n,
      });
    }
    let raw = read_bytes(data, n)?;
    let flags = CompactFlags::try_from_base(raw[0]).ok_or_else(|| DecodeError::InvalidValue {
      expected: CompactFlags::variants()
        .iter()
        .map(|f| u64::from(f.to_base()))
        .collect(),
      actual: u64::from(raw[0]),
    })?;
    let mut arr = [0u8; ECDSA_SIG_LEN];
    arr.copy_from_slice(&raw[1..]);
    Ok(Self {
      flags,
      sig: EcdsaSigBytes::from(arr),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(ECDSA_SIG_LEN + 1).encode(buf);
    buf.push(self.flags.to_base());
    let sig = self.sig.as_bytes();
    buf.extend_from_slice(sig); // nosemgrep: codec-no-raw-extend
  }
}

#[cfg(feature = "codec")]
impl_type!(EcdsaRecSigBytes);

impl Hashable for EcdsaRecSigBytes {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    Hash256::from_lendian(sha256d::Hash::hash(&self.to_bytes()).to_byte_array())
  }
}

impl EcdsaRecSigBytes {
  /// The validated header flags.
  ///
  /// Only library-backed operational types need the flags as a unit; the
  /// bag's own accessors go through [`recovery_id`](Self::recovery_id) and
  /// [`is_compressed`](Self::is_compressed).
  #[cfg(feature = "ecdsa")]
  pub(super) fn flags(&self) -> CompactFlags {
    self.flags
  }

  /// Construct from a plain signature bag and pre-validated flags.
  #[cfg(feature = "ecdsa")]
  pub(super) const fn from_flags(sig: EcdsaSigBytes, flags: CompactFlags) -> Self {
    Self { flags, sig }
  }

  /// Construct from a plain signature bag and recovery metadata.
  ///
  /// Returns `None` when `recovery_id` is outside `0..=3`.
  pub fn from_parts(sig: EcdsaSigBytes, recovery_id: u8, compressed: Compression) -> Option<Self> {
    Some(Self {
      flags: CompactFlags::new(recovery_id, compressed)?,
      sig,
    })
  }

  /// Construct from a raw 65-byte buffer.
  ///
  /// Returns `None` when the header byte is outside the `27..=34` range that
  /// encodes a recovery id and compression flag.
  pub fn from_raw(bytes: [u8; ECDSA_SIG_LEN + 1]) -> Option<Self> {
    let flags = CompactFlags::try_from_base(bytes[0])?;
    let mut arr = [0u8; ECDSA_SIG_LEN];
    arr.copy_from_slice(&bytes[1..]);
    Some(Self {
      flags,
      sig: EcdsaSigBytes::from(arr),
    })
  }

  /// Whether the signing key was compressed.
  pub fn is_compressed(&self) -> bool {
    self.flags.is_compressed()
  }

  /// Recovery ID.
  pub fn recovery_id(&self) -> u8 {
    self.flags.recovery_id()
  }

  /// The plain signature bytes without the header.
  pub fn signature(&self) -> EcdsaSigBytes {
    self.sig
  }

  /// The full 65-byte encoding.
  pub fn to_bytes(&self) -> [u8; ECDSA_SIG_LEN + 1] {
    let mut out = [0u8; ECDSA_SIG_LEN + 1];
    out[0] = self.flags.to_base();
    out[1..].copy_from_slice(self.sig.as_bytes());
    out
  }
}

impl fmt::Debug for EcdsaRecSigBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "EcdsaRecSigBytes(recid={}, compressed={})",
      self.recovery_id(),
      self.is_compressed()
    )
  }
}

impl fmt::Display for EcdsaRecSigBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in self.to_bytes() {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}

type_cvrt!(From<EcdsaRecSigBytes> for EcdsaSigBytes, |rec| {
  rec.signature()
});

cfg_if! {
  if #[cfg(feature = "serde")] {
    use dash_types::serialize::hex as serde_hex;
    use serde::de::Error as DeError;
    use serde::{Deserializer, Serializer};

    impl ::serde::Serialize for EcdsaRecSigBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_hex::serialize(&self.to_bytes(), serializer)
      }
    }

    impl<'de> ::serde::Deserialize<'de> for EcdsaRecSigBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let arr: [u8; ECDSA_SIG_LEN + 1] = serde_hex::deserialize::<_, Vec<u8>>(deserializer)?
          .as_slice()
          .try_into()
          .map_err(|_| DeError::custom("invalid compact recoverable signature length"))?;
        Self::from_raw(arr).ok_or_else(|| DeError::custom("invalid compact signature header"))
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{CompactFlags, Compression, EcdsaRecSigBytes, EcdsaSigBytes, ECDSA_SIG_LEN};
  use crate::prelude::*;

  use dash_types::codec::{BaseCodec, DecodeError};
  use rstest::*;

  fn sig_bag(fill: u8) -> EcdsaSigBytes {
    EcdsaSigBytes::from([fill; ECDSA_SIG_LEN])
  }

  #[rstest]
  fn codec_is_length_prefixed() {
    let rec = EcdsaRecSigBytes::from_parts(sig_bag(0xab), 1, Compression::Compressed).unwrap();
    let mut buf = Vec::new();
    rec.encode(&mut buf);
    assert_eq!(buf.len(), ECDSA_SIG_LEN + 2);
    assert_eq!(buf[0] as usize, ECDSA_SIG_LEN + 1);
    let decoded = EcdsaRecSigBytes::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded, rec);
  }

  #[rstest]
  fn decode_rejects_bad_header() {
    let mut buf = Vec::new();
    EcdsaRecSigBytes::from_parts(sig_bag(0), 0, Compression::Uncompressed)
      .unwrap()
      .encode(&mut buf);
    buf[1] = 0x00;
    assert!(matches!(
      EcdsaRecSigBytes::decode(&mut buf.as_slice()),
      Err(DecodeError::InvalidValue { .. })
    ));
  }

  #[rstest]
  #[case(0, Compression::Uncompressed)]
  #[case(0, Compression::Compressed)]
  #[case(1, Compression::Uncompressed)]
  #[case(1, Compression::Compressed)]
  #[case(2, Compression::Uncompressed)]
  #[case(2, Compression::Compressed)]
  #[case(3, Compression::Uncompressed)]
  #[case(3, Compression::Compressed)]
  fn flags_roundtrip(#[case] rid: u8, #[case] compressed: Compression) {
    let flags = CompactFlags::new(rid, compressed).unwrap();
    assert_eq!(flags.recovery_id(), rid);
    assert_eq!(flags.is_compressed(), compressed.is_compressed());
    assert_eq!(CompactFlags::try_from_base(flags.to_base()), Some(flags));
  }

  #[rstest]
  fn from_raw_rejects_bad_header() {
    let mut buf = [0u8; ECDSA_SIG_LEN + 1];
    buf[0] = 0x00;
    assert!(EcdsaRecSigBytes::from_raw(buf).is_none());

    buf[0] = CompactFlags::Compressed3.to_base() + 1;
    assert!(EcdsaRecSigBytes::from_raw(buf).is_none());
  }

  #[rstest]
  fn header_byte_encoding() {
    let rec = EcdsaRecSigBytes::from_parts(sig_bag(0), 1, Compression::Compressed).unwrap();
    assert_eq!(rec.to_bytes()[0], CompactFlags::Compressed1.to_base());

    let rec = EcdsaRecSigBytes::from_parts(sig_bag(0), 3, Compression::Uncompressed).unwrap();
    assert_eq!(rec.to_bytes()[0], CompactFlags::Uncompressed3.to_base());
  }

  #[rstest]
  #[case::valid_0(0, true)]
  #[case::valid_1(1, true)]
  #[case::valid_2(2, true)]
  #[case::valid_3(3, true)]
  #[case::out_of_range_4(4, false)]
  #[case::out_of_range_255(255, false)]
  fn recovery_id_range(#[case] rid: u8, #[case] valid: bool) {
    let result = EcdsaRecSigBytes::from_parts(sig_bag(0), rid, Compression::Compressed);
    assert_eq!(result.is_some(), valid);
    if let Some(rec) = result {
      assert_eq!(rec.recovery_id(), rid);
    }
  }

  #[rstest]
  fn strips_header_to_plain_bag() {
    let sig = sig_bag(0xcd);
    let rec = EcdsaRecSigBytes::from_parts(sig, 2, Compression::Uncompressed).unwrap();
    assert_eq!(EcdsaSigBytes::from(rec), sig);
  }
}
