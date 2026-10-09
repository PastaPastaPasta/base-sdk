//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special transaction payload decoders.
//!
//! Each payload type is decoded from the `extra_payload` field of a
//! `Transaction` whose `tx_type` is not `Spend`. A BLS field takes its scheme
//! from the payload's version or is always basic, and encodes under the
//! scheme its payload gives when encoded. A field under Core's process-wide
//! flag keeps its wire bytes ([`BlsGlobal`](dash_pkc::bls::BlsGlobal)), so
//! no payload needs the flag to decode.

mod assetlock;
mod assetunlock;
mod bls;
mod cbtx;
mod mnhftx;
mod prodistx;
mod proregtx;
mod proupregtx;
mod prouprevtx;
mod proupservtx;
mod proupsharedregtx;
mod proupsharetx;
mod quorum;
mod shares;

use crate::hash_impl;
use crate::prelude::*;
use crate::types::{NIError, NIPurpose, NITrait, NetInfo, NetInfoV1, NetInfoV2};

use dash_num::make_hash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, Checkable};

use core::fmt;

pub use self::assetlock::{AssetLock, AssetLockInvalid};
pub use self::assetunlock::{AssetUnlock, AssetUnlockInvalid};
pub use self::bls::{commitment_bls_scheme, protx_bls_scheme};
pub use self::cbtx::{CbTxInvalid, CoinbaseCommitment};
pub use self::mnhftx::{MnHardFork, MnHardForkInvalid, VERSIONBITS_NUM_BITS};
pub use self::prodistx::ProDisTx;
pub use self::proregtx::ProRegTx;
pub use self::proupregtx::ProUpRegTx;
pub use self::prouprevtx::ProUpRevTx;
pub use self::proupservtx::ProUpServTx;
pub use self::proupsharedregtx::ProUpSharedRegTx;
pub use self::proupsharetx::ProUpShareTx;
pub use self::quorum::{Commitment, CommitmentInvalid, FinalCommitment, QuorumVvecHash};
pub use self::shares::{CollateralShare, CompactSig, PayoutShare, COMPACT_SIG_LEN};

pub use dash_pkc::__private::__EddsaPkHash as PlatformNodeId;

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

/// ProTx version: legacy BLS operator keys (v1).
pub(crate) const PROTX_VERSION_LEGACY_BLS: u16 = 1;

/// ProTx version: basic (IETF) BLS operator keys (v2).
pub(crate) const PROTX_VERSION_BASIC_BLS: u16 = 2;

/// ProTx version: extended network addresses (v3).
pub(crate) const PROTX_VERSION_EXT_ADDR: u16 = 3;

/// Whether Core reads a ProTx payload of this version past the version.
///
/// Core's `ProTxVersion::GetMax(true, true)` is `ExtAddr` at both pins; it
/// reads only the version of version 0 or anything above.
pub(crate) const fn is_known_protx_version(version: u16) -> bool {
  version != 0 && version <= PROTX_VERSION_EXT_ADDR
}

/// Passes a known ProTx version through.
///
/// # Errors
///
/// Returns `DecodeError::InvalidValue` for a version Core reads alone.
pub(crate) fn check_version(version: u16) -> Result<u16, DecodeError> {
  if is_known_protx_version(version) {
    Ok(version)
  } else {
    Err(DecodeError::InvalidValue {
      expected: vec![1, 2, 3],
      actual: u64::from(version),
    })
  }
}

/// Checks that platform fields are consistent with mn_type and version.
pub(super) fn check_platform_fields(
  mn_type: MnType,
  version: u16,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) -> Option<ProTxInvalid> {
  if mn_type == MnType::Evo {
    if platform_node_id.is_none() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
    if version < PROTX_VERSION_EXT_ADDR {
      if platform_p2p_port.is_none() || platform_http_port.is_none() {
        return Some(ProTxInvalid::BadPlatformFields);
      }
    } else if platform_p2p_port.is_some() || platform_http_port.is_some() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
  } else if platform_node_id.is_some() || platform_p2p_port.is_some() || platform_http_port.is_some() {
    return Some(ProTxInvalid::BadPlatformFields);
  }
  None
}

/// The platform node id, P2P port and HTTP port of an Evo node.
pub(super) type PlatformFields = (Option<PlatformNodeId>, Option<u16>, Option<u16>);

/// Reads the platform fields that follow the inputs hash for Evo nodes.
pub(super) fn read_platform_fields(
  data: &mut &[u8],
  mn_type: MnType,
  version: u16,
) -> Result<PlatformFields, DecodeError> {
  if mn_type != MnType::Evo {
    return Ok((None, None, None));
  }
  let node_id = PlatformNodeId::decode(data)?;
  if version < PROTX_VERSION_EXT_ADDR {
    Ok((Some(node_id), Some(u16::decode(data)?), Some(u16::decode(data)?)))
  } else {
    Ok((Some(node_id), None, None))
  }
}

/// Writes the platform fields as [`read_platform_fields`] reads them.
pub(super) fn write_platform_fields(
  buf: &mut impl EncodeBuf,
  mn_type: MnType,
  version: u16,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) {
  if mn_type == MnType::Evo {
    platform_node_id.unwrap_or_default().encode(buf);
    if version < PROTX_VERSION_EXT_ADDR {
      platform_p2p_port.unwrap_or(0).encode(buf);
      platform_http_port.unwrap_or(0).encode(buf);
    }
  }
}

/// Reads the network info a version carries, extended from v3.
pub(super) fn read_net_info(data: &mut &[u8], version: u16) -> Result<NetInfo, DecodeError> {
  if version >= PROTX_VERSION_EXT_ADDR {
    Ok(NetInfo::Extended(NetInfoV2::decode(data)?))
  } else {
    Ok(NetInfo::Legacy(NetInfoV1::decode(data)?))
  }
}

/// Writes the network info as [`read_net_info`] reads it. Validation
/// guarantees the variant matches the version.
pub(super) fn write_net_info(buf: &mut impl EncodeBuf, net_info: &NetInfo, version: u16) {
  if version >= PROTX_VERSION_EXT_ADDR {
    if let NetInfo::Extended(ext) = net_info {
      ext.encode(buf);
    }
  } else if let NetInfo::Legacy(svc) = net_info {
    svc.encode(buf);
  }
}

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum ProTxInvalid {
  /// `bad-protx-version`
  BadVersion { version: u16 },
  /// `bad-protx-evo-version`
  EvoVersionTooLow { version: u16 },
  /// `bad-protx-type`
  BadMnType { mn_type: MnType },
  /// `bad-protx-mode`
  BadMode { mode: u16 },
  /// `bad-protx-key-null`
  NullKey,
  /// `bad-protx-operator-pubkey`
  OperatorKeyMismatch,
  /// `bad-protx-payee`
  BadPayoutScript,
  /// `bad-protx-netinfo-version`
  NetInfoVersionMismatch,
  /// `bad-protx-netinfo-empty`
  NetInfoEmpty,
  /// `bad-protx-netinfo-bad`
  NetInfoInvalid {
    /// The underlying error.
    error: NIError,
  },
  /// `bad-protx-payee-reuse`
  PayoutKeyReuse,
  /// `bad-protx-operator-reward`
  OperatorRewardTooHigh { reward: u16 },
  /// `bad-protx-reason`
  BadReason { reason: crate::support::RevocationReason },
  /// `bad-protx-platform-fields`
  BadPlatformFields,
}

impl fmt::Display for ProTxInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-protx-version: {version}"),
      Self::EvoVersionTooLow { version } => write!(f, "bad-protx-evo-version: {version}"),
      Self::BadMnType { mn_type } => write!(f, "bad-protx-type: {mn_type}"),
      Self::BadMode { mode } => write!(f, "bad-protx-mode: {mode}"),
      Self::NullKey => write!(f, "bad-protx-key-null"),
      Self::OperatorKeyMismatch => write!(f, "bad-protx-operator-pubkey"),
      Self::BadPayoutScript => write!(f, "bad-protx-payee"),
      Self::NetInfoVersionMismatch => write!(f, "bad-protx-netinfo-version"),
      Self::NetInfoEmpty => write!(f, "bad-protx-netinfo-empty"),
      Self::NetInfoInvalid { error } => write!(f, "bad-protx-netinfo-bad: {error}"),
      Self::PayoutKeyReuse => write!(f, "bad-protx-payee-reuse"),
      Self::OperatorRewardTooHigh { reward } => write!(f, "bad-protx-operator-reward: {reward}"),
      Self::BadReason { reason } => write!(f, "bad-protx-reason: {reason}"),
      Self::BadPlatformFields => write!(f, "bad-protx-platform-fields"),
    }
  }
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
#[derive(Clone, Debug, Eq, PartialEq, Hash, Unencodable)]
pub struct PayloadError {
  /// Which transaction type was being decoded.
  pub tx_type: TxType,
  /// Human-readable description.
  pub message: String,
}

impl fmt::Display for PayloadError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{} payload: {}", self.tx_type, self.message)
  }
}

/// Structural check failure for a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Unencodable)]
pub enum PayloadInvalid {
  /// Provider transaction check failed.
  ProTx(ProTxInvalid),
  /// Coinbase commitment check failed.
  CbTx(CbTxInvalid),
  /// Hard-fork signal check failed.
  MnHardFork(MnHardForkInvalid),
  /// Asset lock check failed.
  AssetLock(AssetLockInvalid),
  /// Asset unlock check failed.
  AssetUnlock(AssetUnlockInvalid),
  /// Quorum commitment check failed.
  Commitment(CommitmentInvalid),
  /// Unrecognized special transaction.
  UnknownType(TxType),
}

impl fmt::Display for PayloadInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ProTx(e) => e.fmt(f),
      Self::CbTx(e) => e.fmt(f),
      Self::MnHardFork(e) => e.fmt(f),
      Self::AssetLock(e) => e.fmt(f),
      Self::AssetUnlock(e) => e.fmt(f),
      Self::Commitment(e) => e.fmt(f),
      Self::UnknownType(t) => write!(f, "bad-txns-type: {t}"),
    }
  }
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
      if !is_known_protx_version(version) {
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
