//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::bls::{self, protx_bls_scheme, protx_source};
use super::shares::{self, CollateralShare, CompactSig, PayoutShare};
use super::sighash::{destination_string, hash256, message_bytes, write_tx_header};
use super::{
  check_platform_fields, check_sptx_netinfo, check_version, is_known_protx_version, read_net_info,
  read_platform_fields, write_net_info, write_platform_fields, InputsHash, MnType, ProTxInvalid, MAX_OPERATOR_REWARD,
  PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR,
};
use crate::payload::PlatformNodeId;
use crate::prelude::*;
use crate::types::{NITrait, NetInfo};
use crate::{hash_impl, Transaction, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::BlsLazyPk;
use dash_script::{AddrParams, PubKeyHash, Recipient};
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
  /// scheme (legacy for v1). It encodes as Core serializes a key in use,
  /// under the version's scheme at encoding, and as zeros when invalid,
  /// whether or not it was used before.
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
  /// One consent signature per share, in share order (v3). Encoding writes
  /// what this holds; Core refuses to write a count other than the shares'.
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
  #[serde(default, skip_serializing_if = "is_zero_u32")]
  early_period_blocks: u32,
  #[serde(default, skip_serializing_if = "is_zero_i64", with = "crate::serialize::duffs")]
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
    let pub_key_operator = bls::read_lazy(data, protx_source(version))?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let (script_payout, payouts, shares, join_sigs, early_period_blocks, early_penalty) =
      if version >= PROTX_VERSION_EXT_ADDR {
        let payouts = shares::read_list(data)?;
        let share_count = u8::decode(data)?;
        let shares = shares::read_items(data, share_count)?;
        let join_sigs = shares::read_items(data, share_count)?;
        (
          ScriptPubKeyBuf::new(),
          payouts,
          shares,
          join_sigs,
          u32::decode(data)?,
          i64::decode(data)?,
        )
      } else {
        (ScriptPubKeyBuf::decode(data)?, Vec::new(), Vec::new(), Vec::new(), 0, 0)
      };
    let inputs_hash = InputsHash::decode(data)?;
    let (platform_node_id, platform_p2p_port, platform_http_port) = read_platform_fields(data, mn_type, version)?;
    Ok(Self {
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
      script_payout,
      payouts,
      shares,
      join_sigs,
      early_period_blocks,
      early_penalty,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      vch_sig: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_unsigned(buf);
    self.vch_sig.encode(buf);
  }
}

/// Part of Core's `IsTriviallyValid`, without chain context. The v3 payout
/// and share list rules (`IsPayoutListTriviallyValid`,
/// `IsShareListTriviallyValid`) and the shared-registration rules are
/// dash-evo's; of the payout rules, this checks the scripts and key reuse.
impl Checkable for ProRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if !is_known_protx_version(self.version) {
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

impl ProRegTx {
  /// The payload's `SER_GETHASH` serialization, which leaves out
  /// `vch_sig`. Its SHA256d ends the string an external collateral's key
  /// signs; see [`Self::sign_string`].
  pub fn sig_hash_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode_unsigned(&mut buf);
    buf
  }

  /// Core's `MakeSignString`, which the key of an external collateral signs
  /// as a text message: the payout, the operator reward, the owner and
  /// voting addresses and the payload hash, separated by `|`.
  ///
  /// It depends on the network through the address prefixes in `addr`.
  pub fn sign_string(&self, addr: &AddrParams) -> String {
    let payout = if self.version >= PROTX_VERSION_EXT_ADDR {
      let entries: Vec<String> = self
        .payouts
        .iter()
        .map(|payout| {
          format!(
            "{}:{}",
            destination_string(payout.script_payout.as_bytes(), addr),
            payout.reward
          )
        })
        .collect();
      entries.join(",")
    } else {
      destination_string(self.script_payout.as_bytes(), addr)
    };
    format!(
      "{payout}|{}|{}|{}|{}",
      self.operator_reward,
      self.key_id_owner.to_base58c(addr.pubkey_addr),
      self.key_id_voting.to_base58c(addr.pubkey_addr),
      hash256(&self.sig_hash_bytes()),
    )
  }

  /// The bytes whose SHA256d an external collateral's key signs, Core's
  /// `MessageHash` input for [`Self::sign_string`].
  pub fn sign_message_bytes(&self, addr: &AddrParams) -> Vec<u8> {
    message_bytes(&self.sign_string(addr))
  }

  /// The bytes whose SHA256d each share owner signs to consent to a shared
  /// registration (v24), Core's `MakeSharedRegConsentHash`.
  ///
  /// The digest binds the funding inputs and their sequences, every output,
  /// the share table, the penalty terms and the registrar configuration of
  /// `tx`, the transaction that carries this payload.
  pub fn shared_consent_bytes(&self, tx: &Transaction) -> Vec<u8> {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for input in &tx.inputs {
      input.prevout.encode(&mut inputs);
    }
    for output in &tx.outputs {
      output.encode(&mut outputs);
    }

    let mut buf = Vec::new();
    String::from("DashSharedMNReg").encode(&mut buf);
    self.version.encode(&mut buf);
    write_tx_header(tx, &mut buf);
    hash256(&inputs).encode(&mut buf);
    for input in &tx.inputs {
      input.sequence.encode(&mut buf);
    }
    hash256(&outputs).encode(&mut buf);
    self.mn_type.to_base().encode(&mut buf);
    self.mode.encode(&mut buf);
    write_net_info(&mut buf, &self.net_info, self.version);
    if self.mn_type == MnType::Evo {
      self.platform_node_id.unwrap_or_default().encode(&mut buf);
    }
    self.key_id_voting.encode(&mut buf);
    bls::write_lazy(&self.pub_key_operator, protx_bls_scheme(self.version), &mut buf);
    self.operator_reward.encode(&mut buf);
    shares::write_list(&self.shares, &mut buf);
    self.early_period_blocks.encode(&mut buf);
    self.early_penalty.encode(&mut buf);
    buf
  }

  /// Every field but `vch_sig`, as [`BaseCodec::encode`] writes them.
  fn encode_unsigned(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.mn_type.to_base().encode(buf);
    self.mode.encode(buf);
    self.collateral_hash.encode(buf);
    self.collateral_index.encode(buf);
    write_net_info(buf, &self.net_info, self.version);
    self.key_id_owner.encode(buf);
    bls::write_lazy(&self.pub_key_operator, protx_bls_scheme(self.version), buf);
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
  }
}

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProRegTx {{ v{}, mn_type: {} }}", self.version, self.mn_type)
  }
}

#[cfg(feature = "serde")]
fn is_zero_u32(v: &u32) -> bool {
  *v == 0
}

#[cfg(feature = "serde")]
fn is_zero_i64(v: &i64) -> bool {
  *v == 0
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
      pub_key_operator: bls::lazy_bytes(&tx.pub_key_operator, protx_bls_scheme(tx.version)),
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
      pub_key_operator: BlsLazyPk::from_bytes(&raw.pub_key_operator, protx_source(raw.version)),
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
      let decoded = tx.decode_payload().unwrap();
      assert!(!decoded.is_ok_and(|d| d.is_complete()), "{txid}");
    }
  }
}
