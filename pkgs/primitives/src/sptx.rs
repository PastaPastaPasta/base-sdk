//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared special transaction logic.

use crate::hash_impl;
use crate::payload::{
  AssetLock, AssetLockInvalid, AssetUnlock, AssetUnlockInvalid, CbTxInvalid, CoinbaseCommitment, CommitmentInvalid,
  FinalCommitment, MnHardFork, MnHardForkInvalid,
};
use crate::prelude::*;
use crate::provider::{
  ProDisTx, ProRegTx, ProTxVersion, ProUpRegTx, ProUpRevTx, ProUpServTx, ProUpShareTx, ProUpSharedRegTx,
};
use crate::types::{NIError, NIPurpose, NITrait, NetInfoV2};

use dash_num::make_hash;
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, Checkable};

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

make_hash! {
  /// LLMQ quorum identifier.
  QuorumHash, 32
}

hash_impl!(QuorumHash);

make_hash! {
  /// Hash of serialized transaction inputs.
  InputsHash, 32
}

hash_impl!(InputsHash);

enum_map! {
  /// Dash transaction type, encoded in the upper 16 bits of the version field.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum TxType, u16, Unknown {
    /// Spend transaction (includes legacy coinbase).
    Spend = 0 => "spend",
    /// Masternode registration (type 1).
    ProviderRegister = 1 => "provider_register",
    /// Masternode service address update (type 2).
    ProviderUpdateService = 2 => "provider_update_service",
    /// Masternode registrar key update (type 3).
    ProviderUpdateRegistrar = 3 => "provider_update_registrar",
    /// Masternode revocation (type 4).
    ProviderUpdateRevoke = 4 => "provider_update_revoke",
    /// Coinbase commitment special transaction (type 5).
    CoinbaseCommitment = 5 => "coinbase_commitment",
    /// LLMQ final commitment (type 6).
    QuorumCommitment = 6 => "quorum_commitment",
    /// Masternode hard fork signal (type 7).
    MnhfSignal = 7 => "mnhf_signal",
    /// Asset lock: L1 to platform (type 8).
    AssetLock = 8 => "asset_lock",
    /// Asset unlock: platform to L1 (type 9).
    AssetUnlock = 9 => "asset_unlock",
    /// Shared masternode dissolution (type 10, v24).
    ProviderDissolve = 10 => "provider_dissolve",
    /// Shared masternode share update (type 11, v24).
    ProviderUpdateShare = 11 => "provider_update_share",
    /// Shared masternode registrar update (type 12, v24).
    ProviderUpdateSharedRegistrar = 12 => "provider_update_shared_registrar",
  }
}

impl_num!(TxType, u16);

hash_impl!(TxType);

enum_map! {
  /// Masternode type, used in provider registration and update transactions.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum MnType, u16, Unknown {
    /// Regular masternode.
    Regular = 0 => "regular",
    /// Evolution (Evo) masternode with platform capabilities.
    Evo = 1 => "evo",
  }
}

impl_num!(MnType, u16);

hash_impl!(MnType);

/// Provider transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum ProTxInvalid {
  /// `bad-protx-version`: a version Core reads alone, 0 or above the
  /// highest known.
  #[error("bad-protx-version: {version}")]
  BadVersion { version: u16 },
  /// `bad-protx-evo-version`
  #[error("bad-protx-evo-version: {version}")]
  EvoVersionTooLow { version: ProTxVersion },
  /// `bad-protx-type`
  #[error("bad-protx-type: {mn_type}")]
  BadMnType { mn_type: MnType },
  /// `bad-protx-mode`
  #[error("bad-protx-mode: {mode}")]
  BadMode { mode: u16 },
  /// `bad-protx-key-null`
  #[error("bad-protx-key-null")]
  NullKey,
  /// `bad-protx-operator-pubkey`
  #[error("bad-protx-operator-pubkey")]
  OperatorKeyMismatch,
  /// `bad-protx-payee`
  #[error("bad-protx-payee")]
  BadPayoutScript,
  /// `bad-protx-netinfo-version`
  #[error("bad-protx-netinfo-version")]
  NetInfoVersionMismatch,
  /// `bad-protx-netinfo-empty`
  #[error("bad-protx-netinfo-empty")]
  NetInfoEmpty,
  /// `bad-protx-netinfo-bad`
  #[error("bad-protx-netinfo-bad: {error}")]
  NetInfoInvalid {
    /// The underlying error.
    error: NIError,
  },
  /// `bad-protx-payee-reuse`
  #[error("bad-protx-payee-reuse")]
  PayoutKeyReuse,
  /// `bad-protx-operator-reward`
  #[error("bad-protx-operator-reward: {reward}")]
  OperatorRewardTooHigh { reward: u16 },
  /// `bad-protx-reason`
  #[error("bad-protx-reason: {reason}")]
  BadReason { reason: crate::support::RevocationReason },
  /// `bad-protx-platform-fields`
  #[error("bad-protx-platform-fields")]
  BadPlatformFields,
}

/// Checks that an extended net info payload is trivially valid.
pub(crate) fn check_sptx_netinfo(ext: &NetInfoV2, version: ProTxVersion, mn_type: MnType) -> Option<ProTxInvalid> {
  if let Some(error) = ext.check() {
    return Some(ProTxInvalid::NetInfoInvalid { error });
  }
  if !ext.has_entries(NIPurpose::CoreP2p) {
    return Some(ProTxInvalid::NetInfoEmpty);
  }
  if mn_type == MnType::Regular
    && (ext.has_entries(NIPurpose::PlatformP2p) || ext.has_entries(NIPurpose::PlatformHttps))
  {
    return Some(ProTxInvalid::NetInfoInvalid {
      error: NIError::Malformed,
    });
  }
  if version >= ProTxVersion::ExtAddr
    && mn_type == MnType::Evo
    && (!ext.has_entries(NIPurpose::PlatformP2p) || !ext.has_entries(NIPurpose::PlatformHttps))
  {
    return Some(ProTxInvalid::NetInfoEmpty);
  }
  None
}

/// A decoded special transaction payload.
///
/// Provides a unified dispatch over all Dash special transaction types. Unknown
/// or future types are stored as opaque bytes for forward compatibility.
///
/// A payload holding a lazy BLS field compares as Core's `operator==` does,
/// which may decode the field, so it is neither `Eq` nor `Hash`.
#[derive(Clone, Debug, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[expect(
  clippy::large_enum_variant,
  reason = "decoded BLS fields hold their points; payloads are decoded one at a time"
)]
pub enum SpecialPayload {
  /// Masternode registration (type 1).
  ProviderRegister(ProRegTx),
  /// Masternode service update (type 2).
  ProviderUpdateService(ProUpServTx),
  /// Masternode registrar update (type 3).
  ProviderUpdateRegistrar(ProUpRegTx),
  /// Masternode revocation (type 4).
  ProviderUpdateRevoke(ProUpRevTx),
  /// A provider payload (types 1 to 4) of version 0 or above the highest
  /// known, of which Core reads only the version.
  UnknownProTxVersion {
    /// The transaction type code.
    tx_type: TxType,
    /// The payload version.
    version: u16,
  },
  /// Coinbase commitment (type 5).
  CoinbaseCommitment(CoinbaseCommitment),
  /// LLMQ final commitment (type 6).
  QuorumCommitment(FinalCommitment),
  /// Hard-fork signal (type 7).
  MnhfSignal(MnHardFork),
  /// Asset lock: L1 to Platform (type 8).
  AssetLock(AssetLock),
  /// Asset unlock: Platform to L1 (type 9).
  AssetUnlock(AssetUnlock),
  /// Shared masternode dissolution (type 10).
  ProviderDissolve(ProDisTx),
  /// Shared masternode share update (type 11).
  ProviderUpdateShare(ProUpShareTx),
  /// Shared masternode registrar update (type 12).
  ProviderUpdateSharedRegistrar(ProUpSharedRegTx),
  /// Unrecognized type, stored as raw bytes.
  Unknown {
    /// The transaction type code.
    tx_type: TxType,
    /// The raw extra payload bytes.
    data: Vec<u8>,
  },
}

/// A special payload decoded from the front of a transaction's extra payload.
///
/// Core's `GetTxPayload` rejects a payload its decoder does not read to the
/// end. That rule is the caller's, applied by comparing `consumed` with `len`.
#[derive(Clone, Debug, PartialEq, Unencodable)]
pub struct PayloadDecode {
  /// The decoded payload.
  pub payload: SpecialPayload,
  /// Bytes the payload's decoder read.
  pub consumed: usize,
  /// Bytes in the extra payload.
  pub len: usize,
}

impl PayloadDecode {
  /// Returns `true` when the decoder read every byte, as `GetTxPayload`
  /// requires.
  pub fn is_complete(&self) -> bool {
    self.consumed == self.len
  }

  /// Returns the bytes after the ones the decoder read.
  pub fn trailing(&self) -> usize {
    self.len.saturating_sub(self.consumed)
  }
}

/// Error decoding a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash, thiserror::Error, Unencodable)]
#[error("{tx_type} payload: {message}")]
pub struct PayloadError {
  /// Which transaction type was being decoded.
  pub tx_type: TxType,
  /// Human-readable description.
  pub message: String,
}

/// Structural check failure for a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash, thiserror::Error, Unencodable)]
pub enum PayloadInvalid {
  /// Provider transaction check failed.
  #[error(transparent)]
  ProTx(ProTxInvalid),
  /// Coinbase commitment check failed.
  #[error(transparent)]
  CbTx(CbTxInvalid),
  /// Hard-fork signal check failed.
  #[error(transparent)]
  MnHardFork(MnHardForkInvalid),
  /// Asset lock check failed.
  #[error(transparent)]
  AssetLock(AssetLockInvalid),
  /// Asset unlock check failed.
  #[error(transparent)]
  AssetUnlock(AssetUnlockInvalid),
  /// Quorum commitment check failed.
  #[error(transparent)]
  Commitment(CommitmentInvalid),
  /// Unrecognized special transaction.
  #[error("bad-txns-type: {0}")]
  UnknownType(TxType),
}

impl Checkable for SpecialPayload {
  type Error = PayloadInvalid;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::ProviderRegister(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateService(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateRegistrar(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateRevoke(p) => p.check().map(PayloadInvalid::ProTx),
      Self::UnknownProTxVersion { version, .. } => {
        Some(PayloadInvalid::ProTx(ProTxInvalid::BadVersion { version: *version }))
      }
      Self::CoinbaseCommitment(p) => p.check().map(PayloadInvalid::CbTx),
      Self::QuorumCommitment(p) => p.check().map(PayloadInvalid::Commitment),
      Self::MnhfSignal(p) => p.check().map(PayloadInvalid::MnHardFork),
      Self::AssetLock(p) => p.check().map(PayloadInvalid::AssetLock),
      Self::AssetUnlock(p) => p.check().map(PayloadInvalid::AssetUnlock),
      // Core's trivial checks of the v24 shared-masternode types are dash-evo's.
      Self::ProviderDissolve(_) | Self::ProviderUpdateShare(_) | Self::ProviderUpdateSharedRegistrar(_) => None,
      Self::Unknown { .. } => None,
    }
  }
}

impl SpecialPayload {
  /// Returns `true` for unrecognized transaction types.
  pub fn is_unknown(&self) -> bool {
    matches!(self, Self::Unknown { .. })
  }

  /// Decodes a payload from its transaction type and raw bytes.
  ///
  /// Returns `Unknown` for unrecognized types rather than an error, ensuring
  /// forward compatibility with future transaction types. A provider payload
  /// of an unknown version is [`Self::UnknownProTxVersion`] after its 2-byte
  /// version, as Core reads it.
  ///
  /// # Errors
  ///
  /// Returns `PayloadError` if a recognized type fails to decode.
  pub fn decode(tx_type: TxType, data: &mut &[u8]) -> Result<Self, PayloadError> {
    let err = |e: DecodeError| PayloadError {
      tx_type,
      message: format!("{e}"),
    };
    if matches!(
      tx_type,
      TxType::ProviderRegister
        | TxType::ProviderUpdateService
        | TxType::ProviderUpdateRegistrar
        | TxType::ProviderUpdateRevoke
    ) {
      let mut peek = *data;
      let version = u16::decode(&mut peek).map_err(err)?;
      if ProTxVersion::try_from_base(version).is_none() {
        *data = peek;
        return Ok(Self::UnknownProTxVersion { tx_type, version });
      }
    }
    let decoded = match tx_type {
      TxType::Spend => {
        return Err(PayloadError {
          tx_type,
          message: String::from("spend transactions have no payload"),
        })
      }
      TxType::ProviderRegister => ProRegTx::decode(data).map(Self::ProviderRegister),
      TxType::ProviderUpdateService => ProUpServTx::decode(data).map(Self::ProviderUpdateService),
      TxType::ProviderUpdateRegistrar => ProUpRegTx::decode(data).map(Self::ProviderUpdateRegistrar),
      TxType::ProviderUpdateRevoke => ProUpRevTx::decode(data).map(Self::ProviderUpdateRevoke),
      TxType::CoinbaseCommitment => CoinbaseCommitment::decode(data).map(Self::CoinbaseCommitment),
      TxType::QuorumCommitment => FinalCommitment::decode(data).map(Self::QuorumCommitment),
      TxType::MnhfSignal => MnHardFork::decode(data).map(Self::MnhfSignal),
      TxType::AssetLock => AssetLock::decode(data).map(Self::AssetLock),
      TxType::AssetUnlock => AssetUnlock::decode(data).map(Self::AssetUnlock),
      TxType::ProviderDissolve => ProDisTx::decode(data).map(Self::ProviderDissolve),
      TxType::ProviderUpdateShare => ProUpShareTx::decode(data).map(Self::ProviderUpdateShare),
      TxType::ProviderUpdateSharedRegistrar => ProUpSharedRegTx::decode(data).map(Self::ProviderUpdateSharedRegistrar),
      unknown => {
        let bytes = data.to_vec();
        *data = &[];
        return Ok(Self::Unknown {
          tx_type: unknown,
          data: bytes,
        });
      }
    };
    decoded.map_err(err)
  }
}
