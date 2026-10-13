//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Provider transaction signatures.

use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{BlsSigBytes, BLS_SIG_LEN};
use dash_pkc::ecdsa::ECDSA_REC_SIG_LEN;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
#[cfg(feature = "serde")]
use dash_types::serialize::hex as serde_hex;
use dash_types::type_id::TypeId;
use dash_types::{CompactSize, Hashable, Numeric};
#[cfg(feature = "serde")]
use serde::de::Error as _;
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

/// Decodes a compact signature of 0 or 65 bytes.
fn decode_compact(data: &mut &[u8]) -> Result<Option<[u8; ECDSA_REC_SIG_LEN]>, DecodeError> {
  match CompactSize::decode(data)?.into_len(ECDSA_REC_SIG_LEN)? {
    0 => Ok(None),
    ECDSA_REC_SIG_LEN => <[u8; ECDSA_REC_SIG_LEN]>::decode(data).map(Some),
    actual => Err(DecodeError::BadLen {
      expected: vec![0, ECDSA_REC_SIG_LEN],
      actual,
    }),
  }
}

/// The signature bytes, empty when unsigned.
fn compact_image(sig: Option<&[u8; ECDSA_REC_SIG_LEN]>) -> Vec<u8> {
  sig.map(|s| s.to_vec()).unwrap_or_default()
}

/// Hex form of a compact signature, empty when unsigned.
#[cfg(feature = "serde")]
pub(crate) mod compact_hex {
  use super::*;

  pub(crate) fn serialize<S: Serializer>(
    sig: &Option<[u8; ECDSA_REC_SIG_LEN]>,
    serializer: S,
  ) -> Result<S::Ok, S::Error> {
    serde_hex::serialize(&compact_image(sig.as_ref()), serializer)
  }

  pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
  ) -> Result<Option<[u8; ECDSA_REC_SIG_LEN]>, D::Error> {
    let bytes: Vec<u8> = serde_hex::deserialize(deserializer)?;
    match bytes.len() {
      0 => Ok(None),
      _ => <[u8; ECDSA_REC_SIG_LEN]>::try_from(bytes.as_slice())
        .map(Some)
        .map_err(|_| D::Error::custom("compact signature is not 0 or 65 bytes")),
    }
  }
}

/// Collateral owner signature, empty when the collateral is spent.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct CollateralSig(#[cfg_attr(feature = "serde", serde(with = "compact_hex"))] Option<[u8; ECDSA_REC_SIG_LEN]>);

impl BaseCodec for CollateralSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    decode_compact(data).map(Self)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    compact_image(self.0.as_ref()).encode(buf);
  }
}

impl Hashable for CollateralSig {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(sha256d::Hash::hash(&compact_image(self.0.as_ref())).to_byte_array())
  }
}

impl CollateralSig {
  /// Borrows the signature, `None` when unsigned.
  pub fn as_bytes(&self) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
    self.0.as_ref()
  }
}

/// Owner signature.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct OwnerSig(#[cfg_attr(feature = "serde", serde(with = "compact_hex"))] Option<[u8; ECDSA_REC_SIG_LEN]>);

impl BaseCodec for OwnerSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    decode_compact(data).map(Self)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    compact_image(self.0.as_ref()).encode(buf);
  }
}

impl Hashable for OwnerSig {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(sha256d::Hash::hash(&compact_image(self.0.as_ref())).to_byte_array())
  }
}

impl OwnerSig {
  /// Borrows the signature, `None` when unsigned.
  pub fn as_bytes(&self) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
    self.0.as_ref()
  }
}

/// Operator signature, zero-filled when unsigned.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct OperatorSig(BlsSigBytes);

impl BaseCodec for OperatorSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    BlsSigBytes::decode(data).map(Self)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

impl Hashable for OperatorSig {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    self.0.hash()
  }
}

impl OperatorSig {
  /// Borrows the signature bytes.
  pub fn as_bytes(&self) -> &BlsSigBytes {
    &self.0
  }
}

impl Default for OperatorSig {
  fn default() -> Self {
    Self(BlsSigBytes::from_bytes([0; BLS_SIG_LEN]))
  }
}
