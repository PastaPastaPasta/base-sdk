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

/// Whether an operator key is not null and passes
/// [`BlsPkBytes::is_canonical`] under the scheme `version` sets. The
/// reference implementation reads the key the same way.
pub(crate) fn is_valid_operator_key(version: ProTxVersion, key: &BlsPkBytes) -> bool {
  !key.is_null()
    && if version == ProTxVersion::LegacyBls {
      key.is_canonical::<BlsScChia>()
    } else {
      key.is_canonical::<BlsScIetf>()
    }
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

  /// A key that both schemes read as valid, class `sub_100` of the corpus
  /// `KeyEdit` names.
  pub(crate) fn subgroup_key() -> BlsPkBytes {
    BlsPkBytes::from_bytes(arr_from_hex(
      "8d9442274d08e7b1081f5814cda5fde2f0e6a06a67d4f39abccc2684c5eefc227560ac86c53b5a57c60f8502d6a7e9e9",
    ))
  }

  /// An edit of an operator key for the payload checks.
  ///
  /// The fixed keys are the first input of their class in the `bls_read`
  /// corpus of `dash-pkc` (pkgs/pkc/corpus/bls_read.json5), which gives the
  /// reference implementation's read of each input under both schemes.
  #[derive(Clone, Copy, Debug)]
  pub(crate) enum KeyEdit {
    /// The key unchanged.
    Kept,
    /// All zero bytes.
    Null,
    /// An x coordinate with no point on the curve, class `off_100`.
    OffCurve,
    /// A point on the curve outside the prime-order subgroup, class
    /// `nonsub_100`.
    OffSubgroup,
    /// The point at infinity, class `identity`, which neither scheme reads
    /// as a valid key.
    Infinity,
    /// A key that only the basic scheme reads as valid, class `sub_101`.
    BasicOnly,
    /// The key with the top bit of its first byte cleared.
    TopBitCleared,
  }

  impl KeyEdit {
    /// `key` after the edit.
    pub(crate) fn apply(self, key: BlsPkBytes) -> BlsPkBytes {
      match self {
        Self::Kept => key,
        Self::Null => BlsPkBytes::default(),
        Self::OffCurve => BlsPkBytes::from_bytes(arr_from_hex(
          "8b986bd86ff720c2e365b402e15a318f391d36d5765bfb13f349957b44271b12bf3d3ddc6b772f0829942d5bdd4e7373",
        )),
        Self::OffSubgroup => BlsPkBytes::from_bytes(arr_from_hex(
          "82643f2e299b6335c36055b5846e38a31d4d9fd914ea92b5cf1d0ea722693fb407135b8dd410ad6cb71fffb86545757f",
        )),
        Self::BasicOnly => BlsPkBytes::from_bytes(arr_from_hex(
          "a02690bff240480310e84737ef6976b3010b637448a41e05d162d55fefb5db45e97980da3d8f0dc470d634b6f8d5b69e",
        )),
        Self::Infinity => {
          let mut bytes = [0; 48];
          bytes[0] = 0xc0;
          BlsPkBytes::from_bytes(bytes)
        }
        Self::TopBitCleared => {
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
  #[case::core_v24(ProTxVersion::CoreV24, false)]
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
