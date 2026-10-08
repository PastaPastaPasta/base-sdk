//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::bls::{self, protx_scheme};
use super::shares::{self, CollateralShare, CompactSig, PayoutShare};
use super::{
  check_sptx_netinfo, check_version, InputsHash, MnType, ProTxInvalid, MAX_OPERATOR_REWARD, PROTX_VERSION_BASIC_BLS,
  PROTX_VERSION_EXT_ADDR,
};
use crate::payload::PlatformNodeId;
use crate::prelude::*;
use crate::types::{NITrait, NetInfo, NetInfoV1, NetInfoV2};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::{BlsLazyPk, BlsSchemeSource};
use dash_script::{PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_type, Checkable, Numeric};

use core::fmt;

/// ProRegTx -- register a new masternode (type 1).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (extended network info, owner payouts and shares)
///
/// Fields a version does not carry hold Core's defaults: an empty
/// `script_payout` from v3, empty lists and zeros below v3.
#[derive(Clone, Debug, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ProRegTxSerde", from = "ProRegTxSerde"))]
pub struct ProRegTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// Masternode type (Regular or Evo).
  pub mn_type: MnType,
  /// Reserved, always 0.
  pub mode: u16,
  /// Collateral hash.
  pub collateral_hash: TxHash,
  /// Collateral index.
  pub collateral_index: u32,
  /// Legacy ServiceV1 or extended NetInfo.
  pub net_info: NetInfo,
  /// Owner key id (20 bytes).
  pub key_id_owner: PubKeyHash,
  /// Operator BLS public key, decoded on first use under the version's
  /// scheme (legacy for v1).
  pub pub_key_operator: BlsLazyPk,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Operator reward in basis points (0-10000).
  pub operator_reward: u16,
  /// Payout script (below v3).
  pub script_payout: ScriptPubKeyBuf,
  /// Owner payouts (v3).
  pub payouts: Vec<PayoutShare>,
  /// Collateral shares of a shared masternode (v3).
  pub shares: Vec<CollateralShare>,
  /// One consent signature per share, in share order (v3).
  pub join_sigs: Vec<CompactSig>,
  /// Blocks in which leaving a shared masternode costs a penalty (v3).
  pub early_period_blocks: u32,
  /// Penalty for leaving early, in duffs (v3).
  pub early_penalty: i64,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  pub platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  pub platform_http_port: Option<u16>,
  /// Owner ECDSA signature (variable-length).
  pub vch_sig: Vec<u8>,
}

impl_type!(ProRegTx);

/// The serde form of [`ProRegTx`], with the operator key as raw bytes.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct ProRegTxSerde {
  version: u16,
  mn_type: MnType,
  mode: u16,
  collateral_hash: TxHash,
  collateral_index: u32,
  net_info: NetInfo,
  key_id_owner: PubKeyHash,
  #[serde(with = "dash_types::serialize::hex")]
  pub_key_operator: [u8; dash_pkc::bls::BLS_PK_LEN],
  key_id_voting: PubKeyHash,
  operator_reward: u16,
  script_payout: ScriptPubKeyBuf,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  payouts: Vec<PayoutShare>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  shares: Vec<CollateralShare>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  join_sigs: Vec<CompactSig>,
  #[serde(default)]
  early_period_blocks: u32,
  #[serde(default, with = "crate::serialize::duffs")]
  early_penalty: i64,
  inputs_hash: InputsHash,
  platform_node_id: Option<PlatformNodeId>,
  #[serde(rename = "platformP2PPort")]
  platform_p2p_port: Option<u16>,
  #[serde(rename = "platformHTTPPort")]
  platform_http_port: Option<u16>,
  #[serde(with = "dash_types::serialize::hex")]
  vch_sig: Vec<u8>,
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

impl BaseCodec for ProRegTx {
  /// Decodes a payload of a known version.
  ///
  /// Core reads only the version of an unknown one, which
  /// [`SpecialPayload::decode`](super::SpecialPayload::decode) reports.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = check_version(u16::decode(data)?)?;
    let mn_type = MnType::from_base(u16::decode(data)?);
    let mode = u16::decode(data)?;
    let collateral_hash = TxHash::decode(data)?;
    let collateral_index = u32::decode(data)?;
    let net_info = read_net_info(data, version)?;
    let key_id_owner = PubKeyHash::decode(data)?;
    let pub_key_operator = bls::read_lazy(data, BlsSchemeSource::Version(protx_scheme(version)))?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let mut tx = Self {
      version,
      mn_type,
      mode,
      collateral_hash,
      collateral_index,
      net_info,
      key_id_owner,
      pub_key_operator,
      key_id_voting,
      operator_reward,
      script_payout: ScriptPubKeyBuf::new(),
      payouts: Vec::new(),
      shares: Vec::new(),
      join_sigs: Vec::new(),
      early_period_blocks: 0,
      early_penalty: 0,
      inputs_hash: InputsHash::default(),
      platform_node_id: None,
      platform_p2p_port: None,
      platform_http_port: None,
      vch_sig: Vec::new(),
    };
    if version >= PROTX_VERSION_EXT_ADDR {
      tx.payouts = shares::read_list(data)?;
      let share_count = u8::decode(data)?;
      tx.shares = shares::read_items(data, share_count)?;
      tx.join_sigs = shares::read_items(data, share_count)?;
      tx.early_period_blocks = u32::decode(data)?;
      tx.early_penalty = i64::decode(data)?;
    } else {
      tx.script_payout = ScriptPubKeyBuf::decode(data)?;
    }
    tx.inputs_hash = InputsHash::decode(data)?;
    (tx.platform_node_id, tx.platform_p2p_port, tx.platform_http_port) = read_platform_fields(data, mn_type, version)?;
    tx.vch_sig = Vec::decode(data)?;
    Ok(tx)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.mn_type.to_base().encode(buf);
    self.mode.encode(buf);
    self.collateral_hash.encode(buf);
    self.collateral_index.encode(buf);
    write_net_info(buf, &self.net_info, self.version);
    self.key_id_owner.encode(buf);
    bls::write_lazy(&self.pub_key_operator, buf);
    self.key_id_voting.encode(buf);
    self.operator_reward.encode(buf);
    if self.version >= PROTX_VERSION_EXT_ADDR {
      shares::write_list(&self.payouts, buf);
      shares::write_list(&self.shares, buf);
      shares::write_items(&self.join_sigs, buf);
      self.early_period_blocks.encode(buf);
      self.early_penalty.encode(buf);
    } else {
      self.script_payout.encode(buf);
    }
    self.inputs_hash.encode(buf);
    write_platform_fields(
      buf,
      self.mn_type,
      self.version,
      &self.platform_node_id,
      self.platform_p2p_port,
      self.platform_http_port,
    );
    self.vch_sig.encode(buf);
  }
}

impl Checkable for ProRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > PROTX_VERSION_EXT_ADDR {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mn_type == MnType::Evo && self.version < PROTX_VERSION_BASIC_BLS {
      return Some(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }
    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }
    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    let shared = !self.shares.is_empty();
    if (!shared && self.key_id_owner.is_null()) || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if !self.pub_key_operator.get().is_valid() {
      return Some(ProTxInvalid::NullKey);
    }

    // Owner payouts: the one script below v3, the list from v3.
    let scripts: Vec<&[u8]> = if self.version >= PROTX_VERSION_EXT_ADDR {
      self.payouts.iter().map(|p| p.script_payout.as_bytes()).collect()
    } else {
      vec![self.script_payout.as_bytes()]
    };
    for script in &scripts {
      match Recipient::from_script(script) {
        Some(Recipient::PubKeyHash(hash)) => {
          if hash == self.key_id_owner || hash == self.key_id_voting {
            return Some(ProTxInvalid::PayoutKeyReuse);
          }
        }
        Some(Recipient::ScriptHash(_)) => {}
        _ => return Some(ProTxInvalid::BadPayoutScript),
      }
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= PROTX_VERSION_EXT_ADDR) {
      return Some(ProTxInvalid::NetInfoVersionMismatch);
    }

    if !self.net_info.is_empty() {
      match &self.net_info {
        NetInfo::Legacy(addr) => {
          if let Some(error) = addr.check() {
            return Some(ProTxInvalid::NetInfoInvalid { error });
          }
        }
        NetInfo::Extended(addr) => {
          if let Some(e) = check_sptx_netinfo(addr, self.version, self.mn_type) {
            return Some(e);
          }
        }
      }
    }

    if let Some(e) = check_platform_fields(
      self.mn_type,
      self.version,
      &self.platform_node_id,
      self.platform_p2p_port,
      self.platform_http_port,
    ) {
      return Some(e);
    }

    if self.operator_reward > MAX_OPERATOR_REWARD {
      return Some(ProTxInvalid::OperatorRewardTooHigh {
        reward: self.operator_reward,
      });
    }

    None
  }
}

hash_impl!(ProRegTx);

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProRegTx {{ v{}, mn_type: {} }}", self.version, self.mn_type)
  }
}

#[cfg(feature = "serde")]
impl From<ProRegTx> for ProRegTxSerde {
  fn from(tx: ProRegTx) -> Self {
    Self {
      version: tx.version,
      mn_type: tx.mn_type,
      mode: tx.mode,
      collateral_hash: tx.collateral_hash,
      collateral_index: tx.collateral_index,
      net_info: tx.net_info,
      key_id_owner: tx.key_id_owner,
      pub_key_operator: tx.pub_key_operator.to_bytes(),
      key_id_voting: tx.key_id_voting,
      operator_reward: tx.operator_reward,
      script_payout: tx.script_payout,
      payouts: tx.payouts,
      shares: tx.shares,
      join_sigs: tx.join_sigs,
      early_period_blocks: tx.early_period_blocks,
      early_penalty: tx.early_penalty,
      inputs_hash: tx.inputs_hash,
      platform_node_id: tx.platform_node_id,
      platform_p2p_port: tx.platform_p2p_port,
      platform_http_port: tx.platform_http_port,
      vch_sig: tx.vch_sig,
    }
  }
}

#[cfg(feature = "serde")]
impl From<ProRegTxSerde> for ProRegTx {
  fn from(raw: ProRegTxSerde) -> Self {
    Self {
      version: raw.version,
      mn_type: raw.mn_type,
      mode: raw.mode,
      collateral_hash: raw.collateral_hash,
      collateral_index: raw.collateral_index,
      net_info: raw.net_info,
      key_id_owner: raw.key_id_owner,
      pub_key_operator: BlsLazyPk::from_bytes(
        &raw.pub_key_operator,
        BlsSchemeSource::Version(protx_scheme(raw.version)),
      ),
      key_id_voting: raw.key_id_voting,
      operator_reward: raw.operator_reward,
      script_payout: raw.script_payout,
      payouts: raw.payouts,
      shares: raw.shares,
      join_sigs: raw.join_sigs,
      early_period_blocks: raw.early_period_blocks,
      early_penalty: raw.early_penalty,
      inputs_hash: raw.inputs_hash,
      platform_node_id: raw.platform_node_id,
      platform_p2p_port: raw.platform_p2p_port,
      platform_http_port: raw.platform_http_port,
      vch_sig: raw.vch_sig,
    }
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::Transaction;

  use dash_dev::{assert_serde_rt, check_sptx, vec_from_hex, Corpus};
  use dash_pkc::bls::BlsCtx;
  use rstest::rstest;

  #[rstest]
  fn corpus_proregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx", check_sptx);
    assert_serde_rt("proregtx", &items);
  }

  /// Version-3 payloads in the v23.1 layout do not decode in the v24 layout,
  /// as v24.0.0-rc.3's `GetTxPayload` rejects them (`payload_core.json5`).
  #[rstest]
  fn corpus_proregtx_v23_layout_fails_in_v24_layout() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx").into_value();
    let entries = corpus["proregtx_v23_layout"].as_object().unwrap();
    assert_eq!(entries.len(), 3);
    for (txid, entry) in entries {
      let raw = vec_from_hex(entry["raw"].as_str().unwrap());
      let tx = Transaction::decode(&mut &raw[..]).unwrap();
      let decoded = tx.decode_payload(BlsCtx::BASIC).unwrap();
      assert!(!decoded.is_ok_and(|d| d.is_complete()), "{txid}");
    }
  }
}
