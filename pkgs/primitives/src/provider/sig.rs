//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Provider transaction signatures.

use super::ProTxVersion;
use crate::prelude::*;
use crate::sign::verify_bls;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{BlsError, BlsPkBytes, BlsScChia, BlsScIetf, BlsSigBytes, BLS_SIG_LEN};
use dash_pkc::ecdsa::ECDSA_REC_SIG_LEN;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
#[cfg(feature = "serde")]
use dash_types::serialize::hex as serde_hex;
use dash_types::type_id::TypeId;
use dash_types::{Hashable, Numeric};
#[cfg(feature = "serde")]
use serde::de::Error as _;
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

/// The compact signature `bytes` hold, `None` unless they are 65 bytes.
fn compact_view(bytes: &[u8]) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
  bytes.try_into().ok()
}

/// Hex form of a compact signature, empty when unsigned.
#[cfg(feature = "serde")]
pub(crate) mod compact_hex {
  use super::*;

  /// The signature bytes, empty when unsigned.
  fn compact_image(sig: Option<&[u8; ECDSA_REC_SIG_LEN]>) -> Vec<u8> {
    sig.map(|s| s.to_vec()).unwrap_or_default()
  }

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

/// Checks an operator signature over `digest` under the scheme `version` sets.
pub(crate) fn verify_operator(
  version: ProTxVersion,
  digest: &[u8],
  sig: &OperatorSig,
  key: &BlsPkBytes,
) -> Result<(), BlsError> {
  if version == ProTxVersion::LegacyBls {
    verify_bls::<BlsScChia>(digest, sig.as_bytes(), key)
  } else {
    verify_bls::<BlsScIetf>(digest, sig.as_bytes(), key)
  }
}

/// Collateral owner signature, empty when the collateral is spent.
///
/// Held as the bytes read, of any length, as the reference decoder reads them.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct CollateralSig(#[cfg_attr(feature = "serde", serde(with = "serde_hex"))] Vec<u8>);

impl BaseCodec for CollateralSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Vec::decode(data).map(Self)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

impl Hashable for CollateralSig {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(sha256d::Hash::hash(&self.0).to_byte_array())
  }
}

impl CollateralSig {
  pub(crate) fn new(sig: [u8; ECDSA_REC_SIG_LEN]) -> Self {
    Self(sig.to_vec())
  }

  /// Borrows the signature, `None` when unsigned or not 65 bytes.
  pub fn as_bytes(&self) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
    compact_view(&self.0)
  }

  /// Borrows the bytes as read, empty when unsigned.
  pub fn as_slice(&self) -> &[u8] {
    &self.0
  }
}

/// Owner signature.
///
/// Held as the bytes read, of any length, as the reference decoder reads them.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct OwnerSig(#[cfg_attr(feature = "serde", serde(with = "serde_hex"))] Vec<u8>);

impl BaseCodec for OwnerSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Vec::decode(data).map(Self)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

impl Hashable for OwnerSig {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_lendian(sha256d::Hash::hash(&self.0).to_byte_array())
  }
}

impl OwnerSig {
  pub(crate) fn new(sig: [u8; ECDSA_REC_SIG_LEN]) -> Self {
    Self(sig.to_vec())
  }

  /// Borrows the signature, `None` when unsigned or not 65 bytes.
  pub fn as_bytes(&self) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
    compact_view(&self.0)
  }

  /// Borrows the bytes as read, empty when unsigned.
  pub fn as_slice(&self) -> &[u8] {
    &self.0
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
  pub(crate) fn new(bytes: BlsSigBytes) -> Self {
    Self(bytes)
  }

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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::sign::tests::bls_sign;

  use rstest::rstest;

  /// Any header byte survives a decode and encode round trip.
  #[rstest]
  #[case::canonical(0x1F)]
  #[case::below_range(0x00)]
  #[case::above_range(0xAB)]
  fn compact_keeps_the_header(#[case] header: u8) {
    let mut wire = vec![65; 66];
    wire[1] = header;
    let sig = OwnerSig::decode(&mut wire.as_slice()).unwrap();
    let mut buf = Vec::new();
    sig.encode(&mut buf);
    assert_eq!(buf, wire);
  }

  /// A signature of any length decodes and encodes back unchanged, as the
  /// reference decoder reads it; only 65 bytes give a compact signature.
  #[rstest]
  #[case::empty(0)]
  #[case::one(1)]
  #[case::short(64)]
  #[case::compact(ECDSA_REC_SIG_LEN)]
  #[case::long(66)]
  #[case::wide_size(300)]
  fn any_length_round_trips(#[case] len: usize) {
    let mut wire = Vec::new();
    vec![7_u8; len].encode(&mut wire);
    let owner = OwnerSig::decode(&mut wire.as_slice()).unwrap();
    let collateral = CollateralSig::decode(&mut wire.as_slice()).unwrap();
    for (bytes, compact) in [
      (owner.as_slice(), owner.as_bytes().is_some()),
      (collateral.as_slice(), collateral.as_bytes().is_some()),
    ] {
      assert_eq!(bytes.len(), len);
      assert_eq!(compact, len == ECDSA_REC_SIG_LEN);
    }
    let mut buf = Vec::new();
    owner.encode(&mut buf);
    collateral.encode(&mut buf);
    assert_eq!(buf, [wire.clone(), wire].concat());
  }

  #[rstest]
  #[case::legacy_bls(ProTxVersion::LegacyBls, true)]
  #[case::basic_bls(ProTxVersion::BasicBls, false)]
  #[case::ext_addr(ProTxVersion::ExtAddr, false)]
  fn operator_scheme_follows_the_version(#[case] version: ProTxVersion, #[case] legacy: bool) {
    let (legacy_key, legacy_sig) = bls_sign::<BlsScChia>(1, &[7; 32]);
    let (basic_key, basic_sig) = bls_sign::<BlsScIetf>(1, &[7; 32]);
    let legacy_sig = OperatorSig::new(BlsSigBytes::from_bytes(legacy_sig));
    let basic_sig = OperatorSig::new(BlsSigBytes::from_bytes(basic_sig));

    assert_eq!(
      verify_operator(version, &[7; 32], &legacy_sig, &legacy_key).is_ok(),
      legacy
    );
    assert_eq!(
      verify_operator(version, &[7; 32], &basic_sig, &basic_key).is_ok(),
      !legacy
    );
  }
}
