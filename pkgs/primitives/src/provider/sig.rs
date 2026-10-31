//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Provider transaction signatures.

use super::ProTxVersion;
use crate::hash_impl;
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
use dash_types::{dlgt_codec, make_bytes, type_cvrt, CompactSize, Hashable, Numeric};
#[cfg(feature = "serde")]
use serde::de::Error as _;
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use core::convert::Infallible;

make_bytes! {
  /// Compact recoverable ECDSA signature, written without a length.
  EcdsaRecSigArray, ECDSA_REC_SIG_LEN
}

hash_impl!(EcdsaRecSigArray);

/// Decodes a compact signature of 0 or 65 bytes.
fn decode_compact(data: &mut &[u8]) -> Result<Option<EcdsaRecSigArray>, DecodeError> {
  match CompactSize::decode(data)?.into_len(ECDSA_REC_SIG_LEN)? {
    0 => Ok(None),
    ECDSA_REC_SIG_LEN => EcdsaRecSigArray::decode(data).map(Some),
    actual => Err(DecodeError::BadLen {
      expected: vec![0, ECDSA_REC_SIG_LEN],
      actual,
    }),
  }
}

/// The signature bytes, empty when unsigned.
fn compact_image(sig: Option<&impl AsRef<[u8]>>) -> Vec<u8> {
  sig.map(|s| s.as_ref().to_vec()).unwrap_or_default()
}

/// Hex form of a compact signature, empty when unsigned.
#[cfg(feature = "serde")]
pub(crate) mod compact_hex {
  use super::*;

  pub(crate) fn serialize<S: Serializer, T: AsRef<[u8]>>(sig: &Option<T>, serializer: S) -> Result<S::Ok, S::Error> {
    serde_hex::serialize(&compact_image(sig.as_ref()), serializer)
  }

  pub(crate) fn deserialize<'de, D: Deserializer<'de>, T: From<[u8; ECDSA_REC_SIG_LEN]>>(
    deserializer: D,
  ) -> Result<Option<T>, D::Error> {
    let bytes: Vec<u8> = serde_hex::deserialize(deserializer)?;
    match bytes.len() {
      0 => Ok(None),
      _ => <[u8; ECDSA_REC_SIG_LEN]>::try_from(bytes.as_slice())
        .map(|sig| Some(T::from(sig)))
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

/// Whether an operator key is not null and, under the basic scheme, decodes
/// as a public key that encodes back to the same bytes. Legacy-scheme keys
/// keep the null check.
pub(crate) fn is_valid_operator_key(version: ProTxVersion, key: &BlsPkBytes) -> bool {
  !key.is_null() && (version == ProTxVersion::LegacyBls || key.is_canonical::<BlsScIetf>())
}

/// Collateral owner signature, empty when the collateral is spent.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct CollateralSig(#[cfg_attr(feature = "serde", serde(with = "compact_hex"))] Option<EcdsaRecSigArray>);

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
  pub(crate) fn new(sig: [u8; ECDSA_REC_SIG_LEN]) -> Self {
    Self(Some(EcdsaRecSigArray::from_bytes(sig)))
  }

  /// Borrows the signature, `None` when unsigned.
  pub fn as_bytes(&self) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
    self.0.as_ref().map(EcdsaRecSigArray::as_bytes)
  }
}

/// Owner signature.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct OwnerSig(#[cfg_attr(feature = "serde", serde(with = "compact_hex"))] Option<EcdsaRecSigArray>);

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
  pub(crate) fn new(sig: [u8; ECDSA_REC_SIG_LEN]) -> Self {
    Self(Some(EcdsaRecSigArray::from_bytes(sig)))
  }

  /// Borrows the signature, `None` when unsigned.
  pub fn as_bytes(&self) -> Option<&[u8; ECDSA_REC_SIG_LEN]> {
    self.0.as_ref().map(EcdsaRecSigArray::as_bytes)
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

/// Declares a compact signature that names what it signs and delegates its
/// codec to [`EcdsaRecSigArray`].
macro_rules! rec_sig {
  ($(#[$attr:meta])* $name:ident) => {
    $(#[$attr])*
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, TypeId)]
    #[cfg_attr(
      feature = "serde",
      derive(::serde::Serialize, ::serde::Deserialize),
      serde(transparent)
    )]
    pub struct $name(EcdsaRecSigArray);

    dlgt_codec!($name => EcdsaRecSigArray, Hash256, Infallible, ECDSA_REC_SIG_LEN);

    type_cvrt!(From<EcdsaRecSigArray> for $name, |sig| Self(*sig));

    type_cvrt!(From<$name> for EcdsaRecSigArray, |sig| sig.0);

    impl $name {
      /// Borrows the signature bytes.
      pub fn as_bytes(&self) -> &[u8; ECDSA_REC_SIG_LEN] {
        self.0.as_bytes()
      }
    }
  };
}

rec_sig! {
  /// Consent of a collateral share owner to a shared registration.
  JoinSig
}

rec_sig! {
  /// Signature of a share owner dissolving a shared masternode.
  DissolveSig
}

rec_sig! {
  /// Signature of a share owner replacing the keys of a shared masternode.
  SharedRegistrarSig
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
pub(crate) mod tests {
  use super::*;
  use crate::sign::tests::bls_sign;

  use dash_dev::arr_from_hex;
  use rstest::rstest;

  /// An edit of an operator key for the payload checks.
  #[derive(Clone, Copy, Debug)]
  pub(crate) enum KeyEdit {
    /// The key as read.
    Kept,
    /// All zero bytes.
    Null,
    /// An x coordinate with no point on the curve.
    OffCurve,
    /// A point on the curve outside the prime-order subgroup.
    OffSubgroup,
    /// The point at infinity, which the reference implementation refuses as
    /// a null key.
    Infinity,
    /// The key without its compression flag.
    Uncompressed,
  }

  impl KeyEdit {
    /// `key` after the edit.
    pub(crate) fn apply(self, key: BlsPkBytes) -> BlsPkBytes {
      match self {
        Self::Kept => key,
        Self::Null => BlsPkBytes::default(),
        Self::OffCurve => BlsPkBytes::from_bytes(arr_from_hex(
          "83c444d48c33647b9b7621e45aa649a86a98936a47066c6e1a9e26a6970d4cdf3f6f815e6ccda4773362ad045ce45849",
        )),
        Self::OffSubgroup => BlsPkBytes::from_bytes(arr_from_hex(
          "81da98896a3b9167e9163d140ac33463352b5efa191410f015bfe3f636d9605f56c6862ac48c3e6d407e8797391cd88b",
        )),
        Self::Infinity => {
          let mut bytes = [0; 48];
          bytes[0] = 0xc0;
          BlsPkBytes::from_bytes(bytes)
        }
        Self::Uncompressed => {
          let mut bytes = *key.as_bytes();
          bytes[0] &= 0x7f;
          BlsPkBytes::from_bytes(bytes)
        }
      }
    }
  }

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
