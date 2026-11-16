//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Provider transaction signatures and the operator key.

use super::ProTxVersion;
use crate::hash_impl;
use crate::prelude::*;
use crate::sign::verify_bls;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{
  BlsError, BlsPkBytes, BlsPkHash, BlsScChia, BlsScIetf, BlsScheme, BlsSigBytes, BLS_PK_LEN, BLS_SIG_LEN,
};
use dash_pkc::ecdsa::ECDSA_REC_SIG_LEN;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
#[cfg(feature = "serde")]
use dash_types::serialize::hex as serde_hex;
use dash_types::type_id::TypeId;
use dash_types::{dlgt_codec, make_bytes, type_cvrt, Hashable, Numeric};
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

/// Hex form of a compact signature, empty when unsigned.
#[cfg(feature = "serde")]
pub(crate) mod compact_hex {
  use super::*;

  /// The signature bytes, empty when unsigned.
  fn compact_image(sig: Option<&impl AsRef<[u8]>>) -> Vec<u8> {
    sig.map(|s| s.as_ref().to_vec()).unwrap_or_default()
  }

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

/// Collateral owner signature, empty when the collateral is spent.
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
    self.0.as_slice().try_into().ok()
  }

  /// Borrows the bytes as read, empty when unsigned.
  pub fn as_slice(&self) -> &[u8] {
    &self.0
  }
}

/// Owner signature.
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
    self.0.as_slice().try_into().ok()
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

/// Operator BLS public key, all zero when null.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(
  feature = "serde",
  derive(::serde::Serialize, ::serde::Deserialize),
  serde(transparent)
)]
pub struct OperatorKey(BlsPkBytes);

dlgt_codec!(OperatorKey => BlsPkBytes, BlsPkHash, Infallible, BLS_PK_LEN);

impl OperatorKey {
  /// Borrows the key bytes.
  pub fn as_bytes(&self) -> &BlsPkBytes {
    &self.0
  }

  /// Whether the key is not null and passes [`BlsPkBytes::is_canonical`]
  /// under the scheme `version` sets.
  pub fn is_valid(&self, version: ProTxVersion) -> bool {
    if version == ProTxVersion::LegacyBls {
      self.is_valid_under::<BlsScChia>()
    } else {
      self.is_valid_under::<BlsScIetf>()
    }
  }

  /// Whether the key is not null and passes [`BlsPkBytes::is_canonical`]
  /// under `S`.
  pub(crate) fn is_valid_under<S: BlsScheme>(&self) -> bool {
    !self.0.is_null() && self.0.is_canonical::<S>()
  }

  /// Checks an operator signature over `digest` under the scheme `version`
  /// sets.
  ///
  /// # Errors
  ///
  /// Returns what [`verify_bls`] returns under that scheme.
  pub(crate) fn verify(&self, version: ProTxVersion, digest: &[u8], sig: &OperatorSig) -> Result<(), BlsError> {
    if version == ProTxVersion::LegacyBls {
      verify_bls::<BlsScChia>(digest, sig.as_bytes(), &self.0)
    } else {
      verify_bls::<BlsScIetf>(digest, sig.as_bytes(), &self.0)
    }
  }
}

type_cvrt!(From<BlsPkBytes> for OperatorKey, |key| Self(*key));

type_cvrt!(From<OperatorKey> for BlsPkBytes, |key| key.0);

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
mod tests {
  use super::*;
  use crate::provider::{ProUpRevTx, ProUpServTx};
  use crate::sign::tests::bls_sign;
  use crate::{InputsHash, MnType, NetInfo, NetInfoV2, RevocationReason, TxHash};

  use bitcoin_primitives::script::ScriptPubKeyBuf;
  use dash_types::Signable;
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

  /// A signature of any length decodes and encodes back unchanged, through
  /// the codec and through JSON; only 65 bytes give a compact signature.
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
    #[cfg(feature = "serde")]
    {
      dash_dev::assert_json_rt(&owner);
      dash_dev::assert_json_rt(&collateral);
    }
  }

  /// A signature hashes the bytes it holds without their size, as a
  /// fixed-size compact signature of the same bytes hashes.
  #[rstest]
  fn hash_covers_the_bytes_held() {
    let bytes = [9_u8; ECDSA_REC_SIG_LEN];
    let fixed = EcdsaRecSigArray::from_bytes(bytes).hash();
    assert_eq!(OwnerSig::new(bytes).hash(), fixed);
    assert_eq!(CollateralSig::new(bytes).hash(), fixed);
  }

  #[rstest]
  #[case::legacy_bls(ProTxVersion::LegacyBls, true)]
  #[case::basic_bls(ProTxVersion::BasicBls, false)]
  #[case::core_v24(ProTxVersion::CoreV24, false)]
  fn operator_scheme_follows_the_version(#[case] version: ProTxVersion, #[case] legacy: bool) {
    let (legacy_key, legacy_sig) = bls_sign::<BlsScChia>(1, &[7; 32]);
    let (basic_key, basic_sig) = bls_sign::<BlsScIetf>(1, &[7; 32]);
    let legacy_key = OperatorKey::from(legacy_key);
    let basic_key = OperatorKey::from(basic_key);
    let legacy_sig = OperatorSig::new(BlsSigBytes::from_bytes(legacy_sig));
    let basic_sig = OperatorSig::new(BlsSigBytes::from_bytes(basic_sig));

    assert_eq!(legacy_key.verify(version, &[7; 32], &legacy_sig).is_ok(), legacy);
    assert_eq!(basic_key.verify(version, &[7; 32], &basic_sig).is_ok(), !legacy);
  }

  /// Stores an operator signature over the payload of `ptx` and verifies it.
  fn operator_signs<T: Signable<Key = OperatorKey, Context = (), Error = BlsError>>(mut ptx: T) {
    let digest = <[u8; 32]>::try_from(ptx.payload(&())).unwrap();
    let (key, sig) = bls_sign::<BlsScIetf>(1, &digest);
    let key = OperatorKey::from(key);

    assert_eq!(ptx.set_signature(&sig, &key, &()), Ok(()));
    assert_eq!(ptx.verify(&key, &()), None);
  }

  #[rstest]
  fn operator_key_signs_updates() {
    let pro_tx_hash = TxHash::from([0x11; 32]);
    operator_signs(ProUpServTx::new(
      ProTxVersion::CoreV24,
      MnType::Regular,
      pro_tx_hash,
      NetInfo::Extended(NetInfoV2::new(1, Vec::new())),
      ScriptPubKeyBuf::new(),
      InputsHash::default(),
      None,
      None,
      None,
    ));
    operator_signs(ProUpRevTx::new(
      ProTxVersion::CoreV24,
      pro_tx_hash,
      RevocationReason::NotSpecified,
      InputsHash::default(),
    ));
  }
}
