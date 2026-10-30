//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::share::{check_payout_version, check_payouts, check_shares, EVO_COLLATERAL, MAX_REWARD, REGULAR_COLLATERAL};
use super::{CollateralShare, CollateralSig, JoinSig, PayoutShare, ProTxVersion};
use crate::codec::{decode_items, decode_list, encode_items, encode_list, impl_payload};
use crate::prelude::*;
use crate::provider::PlatformNodeId;
use crate::sign::{message_digest, unsigned_digest, verify_compact};
use crate::sptx::{check_sptx_netinfo, InputsHash, MnType, ProTxInvalid, MAX_OPERATOR_REWARD};
use crate::types::{NITrait, NetInfo, NetInfoV1, NetInfoV2, ServiceV1};
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
/// - v3: ExtAddr (extended network info, owner payouts, collateral shares)
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
  /// Payout script (version < 3 only).
  #[getset(get = "pub")]
  script_payout: ScriptPubKeyBuf,
  /// Owner payouts (version 3).
  #[getset(get = "pub")]
  payouts: Vec<PayoutShare>,
  /// Collateral shares, empty unless the collateral is shared (version 3).
  #[getset(get = "pub")]
  shares: Vec<CollateralShare>,
  /// Consent signatures, one per share in share order (version 3).
  #[getset(get = "pub")]
  join_sigs: Vec<JoinSig>,
  /// Early dissolution period in blocks (version 3).
  #[getset(get_copy = "pub")]
  early_period_blocks: u32,
  /// Early dissolution penalty in duffs (version 3).
  #[getset(get_copy = "pub")]
  early_penalty: i64,
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

/// Checks that platform fields are consistent with mn_type and version, and
/// that an Evo node's platform node ID is not null.
pub(super) fn check_platform_fields(
  mn_type: MnType,
  version: ProTxVersion,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) -> Option<ProTxInvalid> {
  if mn_type == MnType::Evo {
    let Some(node_id) = platform_node_id else {
      return Some(ProTxInvalid::BadPlatformFields);
    };
    if node_id.is_null() {
      return Some(ProTxInvalid::NullPlatformNodeId);
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

/// The address a payout script pays, or the script in hex.
fn payee_string(script: &ScriptPubKeyBuf, ctx: &AddrParams) -> String {
  let script = script.as_bytes();
  Recipient::from_script(script)
    .and_then(|r| r.to_base58c(ctx))
    .unwrap_or_else(|| script.to_lower_hex_string())
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
      NetInfo::Legacy(NetInfoV1::new(ServiceV1::decode(data)?))
    };
    let key_id_owner = PubKeyHash::decode(data)?;
    let pub_key_operator = BlsPkBytes::decode(data)?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let (script_payout, payouts) = if version >= ProTxVersion::ExtAddr {
      (ScriptPubKeyBuf::new(), decode_list(data)?)
    } else {
      (ScriptPubKeyBuf::decode(data)?, Vec::new())
    };
    let (shares, join_sigs, early_period_blocks, early_penalty) = if version >= ProTxVersion::ExtAddr {
      let count = u8::decode(data)?;
      let shares = decode_items(data, count)?;
      let join_sigs = decode_items(data, count)?;
      (shares, join_sigs, u32::decode(data)?, i64::decode(data)?)
    } else {
      (Vec::new(), Vec::new(), 0, 0)
    };
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
      payouts,
      shares,
      join_sigs,
      early_period_blocks,
      early_penalty,
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
    if self.version >= ProTxVersion::ExtAddr {
      encode_list(&self.payouts, buf);
      // The signatures reuse the share count, so a signature list of another
      // length does not read back.
      encode_list(&self.shares, buf);
      encode_items(&self.join_sigs, buf);
      self.early_period_blocks.encode(buf);
      self.early_penalty.encode(buf);
    } else {
      self.script_payout.encode(buf);
    }
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
    let payout = if self.version >= ProTxVersion::ExtAddr {
      let payouts: Vec<String> = self
        .payouts
        .iter()
        .map(|p| format!("{}:{}", payee_string(p.script_payout(), ctx), p.reward()))
        .collect();
      payouts.join(",")
    } else {
      payee_string(&self.script_payout, ctx)
    };
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

    let shared = !self.shares.is_empty();
    if self.join_sigs.len() != self.shares.len() {
      return Some(ProTxInvalid::JoinSigCountMismatch {
        sigs: self.join_sigs.len(),
        shares: self.shares.len(),
      });
    }
    if shared && self.version < ProTxVersion::ExtAddr {
      return Some(ProTxInvalid::SharesVersionTooLow { version: self.version });
    }
    if let Some(e) = check_payout_version(self.version, &self.script_payout, &self.payouts) {
      return Some(e);
    }
    if shared {
      if !self.collateral_hash.is_null() {
        return Some(ProTxInvalid::ExternalSharedCollateral);
      }
      if !self.key_id_owner.is_null() {
        return Some(ProTxInvalid::SharedOwnerKey);
      }
      if !self.payouts.is_empty() {
        return Some(ProTxInvalid::SharedPayouts);
      }
    } else {
      if self.early_period_blocks != 0 || self.early_penalty != 0 {
        return Some(ProTxInvalid::UnsharedEarlyTerms);
      }
      if self.key_id_owner.is_null() {
        return Some(ProTxInvalid::NullKey);
      }
    }
    if self.pub_key_operator.is_null() || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    if let Some(e) = self.check_owner_rewards() {
      return Some(e);
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
    payouts: Vec<PayoutShare>,
    shares: Vec<CollateralShare>,
    join_sigs: Vec<JoinSig>,
    early_period_blocks: u32,
    early_penalty: i64,
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
      payouts,
      shares,
      join_sigs,
      early_period_blocks,
      early_penalty,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: CollateralSig::default(),
    }
  }

  /// Checks the collateral shares, or the owner payouts when unshared.
  fn check_owner_rewards(&self) -> Option<ProTxInvalid> {
    if !self.shares.is_empty() {
      let collateral = match self.mn_type {
        MnType::Evo => EVO_COLLATERAL,
        _ => REGULAR_COLLATERAL,
      };
      return check_shares(
        &self.shares,
        collateral,
        self.early_period_blocks,
        self.early_penalty,
        &self.key_id_voting,
      );
    }
    if self.version >= ProTxVersion::ExtAddr {
      return check_payouts(&self.payouts, Some(&self.key_id_owner), &self.key_id_voting);
    }
    let payout = PayoutShare::new(self.script_payout.clone(), MAX_REWARD);
    check_payouts(&[payout], Some(&self.key_id_owner), &self.key_id_voting)
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
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::provider::share::tests::script;

  use dash_dev::{arr_from_hex, assert_serde_rt, check_sptx, Corpus};
  use dash_params::Network;
  use rstest::rstest;

  #[rstest]
  fn corpus_proregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx", check_sptx);
    assert_serde_rt("proregtx", &items);
  }

  /// The payload of `txid` in the corpus.
  fn entry(txid: &str) -> ProRegTx {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    corpus
      .entries::<ProRegTx>("proregtx", |_, _, _| {})
      .remove(txid)
      .unwrap()
  }

  /// A testnet registration with one payout.
  fn registration() -> ProRegTx {
    entry("13ccca675ed8a8a788693f46191e7237e2896701ede3058c20263e1b2343923d")
  }

  /// A regtest registration with two shares.
  fn shared() -> ProRegTx {
    entry("be0bcc4773f4510a7a3afdfd18e7758f007c3ff1eb57c3c7a500620c13a05b9c")
  }

  /// `share` with its refund script paying `key`.
  fn refund_to(share: &CollateralShare, key: PubKeyHash) -> CollateralShare {
    CollateralShare::new(
      share.amount(),
      script(Recipient::PubKeyHash(key)),
      share.script_reward().clone(),
      share.key_id_owner(),
    )
  }

  #[rstest]
  #[case::payout_to_owner(
    registration(),
    |ptx: &mut ProRegTx| ptx.payouts[0] = PayoutShare::new(script(Recipient::PubKeyHash(ptx.key_id_owner)), MAX_REWARD),
    ProTxInvalid::PayoutKeyReuse
  )]
  #[case::unshared_early_period(
    registration(),
    |ptx: &mut ProRegTx| ptx.early_period_blocks = 1,
    ProTxInvalid::UnsharedEarlyTerms
  )]
  #[case::unshared_early_penalty(
    registration(),
    |ptx: &mut ProRegTx| ptx.early_penalty = 1,
    ProTxInvalid::UnsharedEarlyTerms
  )]
  #[case::unshared_null_owner(
    registration(),
    |ptx: &mut ProRegTx| ptx.key_id_owner = PubKeyHash::default(),
    ProTxInvalid::NullKey
  )]
  #[case::shared_external_collateral(
    shared(),
    |ptx: &mut ProRegTx| ptx.collateral_hash = TxHash::from_lendian([1; 32]),
    ProTxInvalid::ExternalSharedCollateral
  )]
  #[case::shared_owner_key(
    shared(),
    |ptx: &mut ProRegTx| ptx.key_id_owner = ptx.shares[0].key_id_owner(),
    ProTxInvalid::SharedOwnerKey
  )]
  #[case::shared_payouts(
    shared(),
    |ptx: &mut ProRegTx| ptx.payouts = registration().payouts,
    ProTxInvalid::SharedPayouts
  )]
  #[case::share_refund_to_voting(
    shared(),
    |ptx: &mut ProRegTx| ptx.shares[0] = refund_to(&ptx.shares[0], ptx.key_id_voting),
    ProTxInvalid::ShareKeyReuse
  )]
  #[case::evo_shares_of_regular_collateral(
    shared(),
    |ptx: &mut ProRegTx| ptx.mn_type = MnType::Evo,
    ProTxInvalid::BadShareAmountSum { total: REGULAR_COLLATERAL }
  )]
  #[case::sig_missing(
    shared(),
    |ptx: &mut ProRegTx| ptx.join_sigs.truncate(1),
    ProTxInvalid::JoinSigCountMismatch { sigs: 1, shares: 2 }
  )]
  #[case::sig_extra(
    shared(),
    |ptx: &mut ProRegTx| ptx.join_sigs.push(ptx.join_sigs[0]),
    ProTxInvalid::JoinSigCountMismatch { sigs: 3, shares: 2 }
  )]
  #[case::sigs_unshared(
    shared(),
    |ptx: &mut ProRegTx| ptx.shares.clear(),
    ProTxInvalid::JoinSigCountMismatch { sigs: 2, shares: 0 }
  )]
  #[case::shares_basic_bls(
    shared(),
    |ptx: &mut ProRegTx| ptx.version = ProTxVersion::BasicBls,
    ProTxInvalid::SharesVersionTooLow { version: ProTxVersion::BasicBls }
  )]
  #[case::payout_version(
    registration(),
    |ptx: &mut ProRegTx| ptx.script_payout = ptx.payouts[0].script_payout().clone(),
    ProTxInvalid::PayoutVersionMismatch { version: ProTxVersion::ExtAddr }
  )]
  #[case::null_platform_node_id(
    entry("2770d2493755b59b3426474b2a18eb5c34df636530ae8059aa1fe4b22ce47c3c"),
    |ptx: &mut ProRegTx| ptx.platform_node_id = Some(PlatformNodeId::default()),
    ProTxInvalid::NullPlatformNodeId
  )]
  #[case::null_platform_node_id_before_ports(
    entry("2770d2493755b59b3426474b2a18eb5c34df636530ae8059aa1fe4b22ce47c3c"),
    |ptx: &mut ProRegTx| {
      ptx.platform_node_id = Some(PlatformNodeId::default());
      ptx.platform_p2p_port = Some(26656);
    },
    ProTxInvalid::NullPlatformNodeId
  )]
  fn check(#[case] mut ptx: ProRegTx, #[case] edit: fn(&mut ProRegTx), #[case] expected: ProTxInvalid) {
    assert_eq!(ptx.check(), None);
    edit(&mut ptx);
    assert_eq!(ptx.check(), Some(expected));
  }

  /// The collateral key of regtest registration `e069aa21` signs its two
  /// payouts. It is the key of output 2 of `d7f51e30` in the same chain.
  #[rstest]
  fn collateral_key_signs_payouts() {
    let ptx = entry("e069aa21a4c70c3cfec548d2fb99004207145cae53c400ae319626c966f471c8");
    let key = PubKeyHash::from_lendian(arr_from_hex("aa20a04ead2af1a823293452a32c6f5b33caccaa"));
    assert_eq!(ptx.payouts.len(), 2);
    assert_eq!(ptx.verify(&key, Network::Regtest.addr()), None);
  }
}
