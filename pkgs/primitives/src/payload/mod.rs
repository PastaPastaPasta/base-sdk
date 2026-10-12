//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special transaction payload decoders.
//!
//! Each payload type is decoded from the `extra_payload` field of a
//! `Transaction` whose `tx_type` is not `Spend`.

mod assetlock;
mod assetunlock;
mod cbtx;
mod mnhftx;
mod proregtx;
mod proupregtx;
mod prouprevtx;
mod proupservtx;
mod quorum;

use crate::hash_impl;
use crate::prelude::*;
use crate::types::{NIError, NIPurpose, NITrait, NetInfoV2};

use dash_num::make_hash;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, Checkable};

pub use self::assetlock::{AssetLock, AssetLockInvalid};
pub use self::assetunlock::{AssetUnlock, AssetUnlockInvalid};
pub use self::cbtx::{CbTxInvalid, CoinbaseCommitment};
pub use self::mnhftx::{MnHardFork, MnHardForkInvalid, VERSIONBITS_NUM_BITS};
pub use self::proregtx::ProRegTx;
pub use self::proupregtx::ProUpRegTx;
pub use self::prouprevtx::ProUpRevTx;
pub use self::proupservtx::ProUpServTx;
pub use self::quorum::{Commitment, CommitmentInvalid, FinalCommitment, QuorumVvecHash};

pub use dash_pkc::__private::__EddsaPkHash as PlatformNodeId;

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

/// ProTx version: legacy BLS operator keys (v1).
#[expect(unused, reason = "consensus constant")]
pub(crate) const PROTX_VERSION_LEGACY_BLS: u16 = 1;

/// ProTx version: basic (IETF) BLS operator keys (v2).
pub(crate) const PROTX_VERSION_BASIC_BLS: u16 = 2;

/// ProTx version: extended network addresses (v3).
pub(crate) const PROTX_VERSION_EXT_ADDR: u16 = 3;

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
  /// `bad-protx-version`
  #[error("bad-protx-version: {version}")]
  BadVersion { version: u16 },
  /// `bad-protx-evo-version`
  #[error("bad-protx-evo-version: {version}")]
  EvoVersionTooLow { version: u16 },
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
pub(crate) fn check_sptx_netinfo(ext: &NetInfoV2, version: u16, mn_type: MnType) -> Option<ProTxInvalid> {
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
  if version >= PROTX_VERSION_EXT_ADDR
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
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum SpecialPayload {
  /// Masternode registration (type 1).
  ProviderRegister(ProRegTx),
  /// Masternode service update (type 2).
  ProviderUpdateService(ProUpServTx),
  /// Masternode registrar update (type 3).
  ProviderUpdateRegistrar(ProUpRegTx),
  /// Masternode revocation (type 4).
  ProviderUpdateRevoke(ProUpRevTx),
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
  /// Unrecognized type, stored as raw bytes.
  Unknown {
    /// The transaction type code.
    tx_type: TxType,
    /// The raw extra payload bytes.
    data: Vec<u8>,
  },
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
      Self::CoinbaseCommitment(p) => p.check().map(PayloadInvalid::CbTx),
      Self::QuorumCommitment(p) => p.check().map(PayloadInvalid::Commitment),
      Self::MnhfSignal(p) => p.check().map(PayloadInvalid::MnHardFork),
      Self::AssetLock(p) => p.check().map(PayloadInvalid::AssetLock),
      Self::AssetUnlock(p) => p.check().map(PayloadInvalid::AssetUnlock),
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
  /// forward compatibility with future transaction types.
  ///
  /// # Errors
  ///
  /// Returns `PayloadError` if a recognized type fails to decode.
  pub fn decode(tx_type: TxType, data: &mut &[u8]) -> Result<Self, PayloadError> {
    use dash_types::codec::{BaseCodec, DecodeError};

    let err = |e: DecodeError| PayloadError {
      tx_type,
      message: format!("{e}"),
    };
    match tx_type {
      TxType::Spend => Err(PayloadError {
        tx_type,
        message: String::from("spend transactions have no payload"),
      }),
      TxType::ProviderRegister => ProRegTx::decode(data).map(Self::ProviderRegister).map_err(err),
      TxType::ProviderUpdateService => ProUpServTx::decode(data).map(Self::ProviderUpdateService).map_err(err),
      TxType::ProviderUpdateRegistrar => ProUpRegTx::decode(data).map(Self::ProviderUpdateRegistrar).map_err(err),
      TxType::ProviderUpdateRevoke => ProUpRevTx::decode(data).map(Self::ProviderUpdateRevoke).map_err(err),
      TxType::CoinbaseCommitment => cbtx::CoinbaseCommitment::decode(data)
        .map(Self::CoinbaseCommitment)
        .map_err(err),
      TxType::QuorumCommitment => FinalCommitment::decode(data).map(Self::QuorumCommitment).map_err(err),
      TxType::MnhfSignal => MnHardFork::decode(data).map(Self::MnhfSignal).map_err(err),
      TxType::AssetLock => assetlock::AssetLock::decode(data).map(Self::AssetLock).map_err(err),
      TxType::AssetUnlock => assetunlock::AssetUnlock::decode(data)
        .map(Self::AssetUnlock)
        .map_err(err),
      unknown => {
        let bytes = data.to_vec();
        *data = &[];
        Ok(Self::Unknown {
          tx_type: unknown,
          data: bytes,
        })
      }
    }
  }
}
