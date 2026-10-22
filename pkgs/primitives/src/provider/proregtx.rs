//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::{CollateralSig, ProTxVersion};
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::provider::PlatformNodeId;
use crate::sign::{message_digest, unsigned_digest, verify_compact};
use crate::sptx::{check_sptx_netinfo, InputsHash, MnType, ProTxInvalid, MAX_OPERATOR_REWARD};
use crate::types::{NITrait, NetInfo, NetInfoV1, NetInfoV2};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_num::Hash256;
use dash_params::AddrParams;
use dash_pkc::bls::BlsPkBytes;
use dash_pkc::ecdsa::{EcdsaError, ECDSA_REC_SIG_LEN};
use dash_script::{PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, Numeric, Signable};
use getset::{CopyGetters, Getters};
use hex_conservative::DisplayHex;

use core::fmt;

/// ProRegTx -- register a new masternode (type 1).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (extended network info)
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProRegTx {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: ProTxVersion,
  /// Masternode type (Regular or Evo).
  #[getset(get_copy = "pub")]
  mn_type: MnType,
  /// Reserved, always 0.
  #[getset(get_copy = "pub")]
  mode: u16,
  /// Collateral hash.
  #[getset(get_copy = "pub")]
  collateral_hash: TxHash,
  /// Collateral index.
  #[getset(get_copy = "pub")]
  collateral_index: u32,
  /// Legacy ServiceV1 or extended NetInfo.
  #[getset(get = "pub")]
  net_info: NetInfo,
  /// Owner key id (20 bytes).
  #[getset(get_copy = "pub")]
  key_id_owner: PubKeyHash,
  /// Operator BLS public key (48 bytes).
  #[getset(get_copy = "pub")]
  pub_key_operator: BlsPkBytes,
  /// Voting key id (20 bytes).
  #[getset(get_copy = "pub")]
  key_id_voting: PubKeyHash,
  /// Operator reward in basis points (0-10000).
  #[getset(get_copy = "pub")]
  operator_reward: u16,
  /// Payout script.
  #[getset(get = "pub")]
  script_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  #[getset(get_copy = "pub")]
  inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  #[getset(get_copy = "pub")]
  platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  #[cfg_attr(feature = "serde", serde(rename = "platformP2PPort"))]
  #[getset(get_copy = "pub")]
  platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  #[getset(get_copy = "pub")]
  platform_http_port: Option<u16>,
  /// Collateral owner ECDSA signature.
  #[cfg_attr(feature = "serde", serde(rename = "vchSig"))]
  #[getset(get = "pub")]
  sig: CollateralSig,
}

impl_payload!(ProRegTx);

/// Checks that platform fields are consistent with mn_type and version.
pub(super) fn check_platform_fields(
  mn_type: MnType,
  version: ProTxVersion,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) -> Option<ProTxInvalid> {
  if mn_type == MnType::Evo {
    if platform_node_id.is_none() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
    if version < ProTxVersion::ExtAddr {
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

impl BaseCodec for ProRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = ProTxVersion::decode(data)?;
    let mn_type = MnType::from_base(u16::decode(data)?);
    let mode = u16::decode(data)?;
    let collateral_hash = TxHash::decode(data)?;
    let collateral_index = u32::decode(data)?;
    let net_info = if version >= ProTxVersion::ExtAddr {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1::decode(data)?)
    };
    let key_id_owner = PubKeyHash::decode(data)?;
    let pub_key_operator = BlsPkBytes::decode(data)?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let script_payout = ScriptPubKeyBuf::decode(data)?;
    let inputs_hash = InputsHash::decode(data)?;
    let (platform_node_id, platform_p2p_port, platform_http_port) = if mn_type == MnType::Evo {
      let node_id = PlatformNodeId::decode(data)?;
      if version < ProTxVersion::ExtAddr {
        (Some(node_id), Some(u16::decode(data)?), Some(u16::decode(data)?))
      } else {
        (Some(node_id), None, None)
      }
    } else {
      (None, None, None)
    };

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
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: CollateralSig::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.mn_type.to_base().encode(buf);
    self.mode.encode(buf);
    self.collateral_hash.encode(buf);
    self.collateral_index.encode(buf);
    // Branch on version to match the decode path. Validation
    // guarantees the variant matches the version.
    if self.version >= ProTxVersion::ExtAddr {
      if let NetInfo::Extended(ext) = &self.net_info {
        ext.encode(buf);
      }
    } else if let NetInfo::Legacy(svc) = &self.net_info {
      svc.encode(buf);
    }
    self.key_id_owner.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.operator_reward.encode(buf);
    self.script_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if self.mn_type == MnType::Evo {
      self.platform_node_id.unwrap_or_default().encode(buf);
      if self.version < ProTxVersion::ExtAddr {
        self.platform_p2p_port.unwrap_or(0).encode(buf);
        self.platform_http_port.unwrap_or(0).encode(buf);
      }
    }
    self.sig.encode(buf);
  }
}

impl Signable for ProRegTx {
  type Key = PubKeyHash;
  type Context = AddrParams;
  type Error = EcdsaError;

  fn payload(&self, ctx: &AddrParams) -> Vec<u8> {
    let payout = self.script_payout.as_bytes();
    let payout = Recipient::from_script(payout)
      .and_then(|r| r.to_base58c(ctx))
      .unwrap_or_else(|| payout.to_lower_hex_string());
    let msg = format!(
      "{payout}|{}|{}|{}|{}",
      self.operator_reward,
      self.key_id_owner.to_base58c(ctx.pubkey_addr),
      self.key_id_voting.to_base58c(ctx.pubkey_addr),
      Hash256::from_lendian(unsigned_digest(self, &self.sig)),
    );
    message_digest(msg.as_bytes()).to_vec()
  }

  fn set_signature(&mut self, sig: &[u8], key: &PubKeyHash, ctx: &AddrParams) -> Result<(), EcdsaError> {
    let sig = <[u8; ECDSA_REC_SIG_LEN]>::try_from(sig).map_err(|_| EcdsaError::InvalidSignature)?;
    verify_compact(&self.payload(ctx), &sig, key)?;
    self.sig = CollateralSig::new(sig);
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.sig = CollateralSig::default();
  }

  fn verify(&self, key: &PubKeyHash, ctx: &AddrParams) -> Option<EcdsaError> {
    let sig = self.sig.as_bytes().ok_or(EcdsaError::InvalidSignature);
    sig.and_then(|sig| verify_compact(&self.payload(ctx), sig, key)).err()
  }
}

impl Checkable for ProRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.mn_type == MnType::Evo && self.version < ProTxVersion::BasicBls {
      return Some(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }
    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }
    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    if self.key_id_owner.is_null() || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.pub_key_operator.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    let recipient = Recipient::from_script(payout);
    match &recipient {
      Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_)) => {}
      _ => return Some(ProTxInvalid::BadPayoutScript),
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= ProTxVersion::ExtAddr) {
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

    if let Some(Recipient::PubKeyHash(hash)) = &recipient {
      if *hash == self.key_id_owner || *hash == self.key_id_voting {
        return Some(ProTxInvalid::PayoutKeyReuse);
      }
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
  /// Constructs an unsigned payload. The signature is set through
  /// [`Signable::set_signature`].
  pub fn new(
    version: ProTxVersion,
    mn_type: MnType,
    mode: u16,
    collateral_hash: TxHash,
    collateral_index: u32,
    net_info: NetInfo,
    key_id_owner: PubKeyHash,
    pub_key_operator: BlsPkBytes,
    key_id_voting: PubKeyHash,
    operator_reward: u16,
    script_payout: ScriptPubKeyBuf,
    inputs_hash: InputsHash,
    platform_node_id: Option<PlatformNodeId>,
    platform_p2p_port: Option<u16>,
    platform_http_port: Option<u16>,
  ) -> Self {
    Self {
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
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: CollateralSig::default(),
    }
  }
}

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "ProRegTx {{ v{}, mn_type: {} }}",
      self.version.to_base(),
      self.mn_type
    )
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx", check_sptx);
    assert_serde_rt("proregtx", &items);
  }
}
