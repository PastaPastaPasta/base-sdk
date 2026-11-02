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
    if version < ProTxVersion::CoreV24 {
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
    let net_info = if version >= ProTxVersion::CoreV24 {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1::decode(data)?)
    };
    let key_id_owner = PubKeyHash::decode(data)?;
    let pub_key_operator = BlsPkBytes::decode(data)?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let (script_payout, payouts) = if version >= ProTxVersion::CoreV24 {
      (ScriptPubKeyBuf::new(), decode_list(data)?)
    } else {
      (ScriptPubKeyBuf::decode(data)?, Vec::new())
    };
    let (shares, join_sigs, early_period_blocks, early_penalty) = if version >= ProTxVersion::CoreV24 {
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
      if version < ProTxVersion::CoreV24 {
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
    if self.version >= ProTxVersion::CoreV24 {
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
    if self.version >= ProTxVersion::CoreV24 {
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
      if self.version < ProTxVersion::CoreV24 {
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
    let payout = if self.version >= ProTxVersion::CoreV24 {
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
    if shared && self.version < ProTxVersion::CoreV24 {
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
    if is_extended != (self.version >= ProTxVersion::CoreV24) {
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

    if self.operator_reward > MAX_OPERATOR_REWARD {
      return Some(ProTxInvalid::OperatorRewardTooHigh {
        reward: self.operator_reward,
      });
    }

    // The reference checks the reward with the payload itself, and the
    // platform fields only after that.
    if let Some(e) = check_platform_fields(
      self.mn_type,
      self.version,
      &self.platform_node_id,
      self.platform_p2p_port,
      self.platform_http_port,
    ) {
      return Some(e);
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
    if self.version >= ProTxVersion::CoreV24 {
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

  use dash_dev::{arr_from_hex, assert_json_rt, assert_serde_rt, check_sptx, check_sptx_raw, vec_from_hex, Corpus};
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

  /// Regtest transactions as txid and raw bytes, from functional tests of the
  /// reference implementation at v24.0.0-rc.4.
  /// `dash-cli -regtest decoderawtransaction <raw>` decodes each one.
  const REGTEST: [(&str, &str); 5] = [
    // feature_masternode_payout_shares.py line 119
    ("e069aa21a4c70c3cfec548d2fb99004207145cae53c400ae319626c966f471c8", "0300010001e1b7fb5c4c16e4f80c6106b139248d5fc5d2a0cdd7c0987ee692f407301ef5d7000000006a47304402207bf329ebb1b53f495fafd1bbedb4bc56f0c848d10d7ceedeb62f79d0357abf0002206c833690189df4c71839870ce96262f83d796a882386096c9db6795d77863d8701210259b7fcb2ca6ca1b24a1513262dee6f3b30fc67044e46f297c56af8223e4986d0feffffff01fbdef505000000001976a9140e00d7c0f238858417090e0527d542936a1889a588ac00000000fd3901030000000000e1b7fb5c4c16e4f80c6106b139248d5fc5d2a0cdd7c0987ee692f407301ef5d702000000010100010101047f000001324a23e9fcc90a2468c346cef7eaac3ab9acfe3dd52d93ef271a050424cc43f4cbd80205efd3f12e54749c547c77ec50c0d7d3c115933495c0d99f24cd5a96f32fb9d6fd7c88b2638afa676c107be6e1cdac662a47f81df28d02c409021976a9149b0a785f5f1e69d38df93e5b8523a5f83d27f25688ac581b1976a9145b79ba429200308a7154d6218ee7f97c0be8b67988acb80b00000000000000000000000000737caa8f48f62a42d8775000b9f32d8c895119a46d524084faf5ae4b478c940c41208e6dd09d35343d2d1480ff66552c87f1aa74632ff9cf3cace42f4d693b9a55543982837d8cb3e2ec44b6a672009d9bb82d0d131e49a3fba5e2296565c69a3a6a"),
    // feature_evo_shares_activation.py line 129
    ("7efe0bfb04d24a359ff58aa52f04d7d9950ecea0619f3e31a09cbab2bd9c7e8b", "03000100013960678afccf780eecf5f03fb534d27aa39ccee737ffbb836a926ea265fb3b28010000006a473044022012c7ab8c6c0695f507042e2e468ac68c0c5087034aa9a83b30f645496b4d5db3022021346e9b189e14a80e46fab00131d06a36d1dce6110b0bab20a6d6e45dbdb29901210333c72ecc4b71f232eacef470d9ee329dc9db9e22701f5b26c427060f7fd29aaefeffffff01d1def505000000001976a914f20e57bce626d74ad278f8aee9ecf670fda3ae9b88ac00000000fd63010300010000003960678afccf780eecf5f03fb534d27aa39ccee737ffbb836a926ea265fb3b2802000000010300010101047f000001329e01010101047f000001368602010101047f0000013a6eccb1cdad72e48f660ca69711fda31170d24d701d80402db35b8cce3962ec46b2c4d1a69ade82e56766390cf662bd878a236e87495a1b9aee88f2838f80b6426f06f011fd3eca7047ce4178fe3a0c568c8bc5e428aade43e30000021976a9149dacaffa7371031433e88a7efe0756c8a5c6f62288ac70171976a914408753da241f0c39ea5e5a501928a4f48c6612e388aca00f000000000000000000000000006d0ac9ab53542d8c86368d7a612f2373ad617e74c17e6beb5398b0d583a84f7f9e320000000000000000000000000000000000004120bcef0bf841f05e656ff2d3ad2052a9c40a7884b0bc05af5bf6f3ed6faf310fd10145dda7fbbf5bbc82325223082b01373041af5806e68e681ee9c6ce87240ef9"),
    // feature_masternode_shares.py line 95
    ("be0bcc4773f4510a7a3afdfd18e7758f007c3ff1eb57c3c7a500620c13a05b9c", "03000100039111ef3c92a6a3d21348787713608ace31c4c06b2614356cd2eec5b75d6d101c010000006a473044022018034cb214cd32ba3f01ba2be33851cf1049c27f7f1fc1a6f918622596abe8910220752b2ba0f78c5ff46ca96e0e64cb717a77a7411b2726bf424438ef7a8ed6588d012102444d4a2da17d087e02e4a783e260e29a527b9ebb45477c34a9a9c084a47fd7bafefffffffd74c6263d8142cbd75edb80d90c3feff4edba714fd7cd1e3181e8d604271298000000006a47304402204148204bb2cfc6434bca64ae4d185b2d5f321f5d5062d5b7ef8646daef6468a002206c3127ddfc22c9d849f910e1a88d45a40a9a887342892f8a1563f9b8f54974760121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffff2f914c0f8d8ca1f6ccbb39143b7a643083e5eb5d750ffa09cafeae34eab444ab000000006a473044022020758e68cc3af9be9be701d03bc329bca642b3215e924d55cba317364db96c0902206f6b8a8d1dc398226e70edff5e77fcfe08f873713e27b7b02b8b25a0b586f8c40121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffff0271aa750f000000001976a9144a3d114c688f411a607eae40be1ee11c72caf11f88ac00e8764817000000070444534843755100000000fdb001030000000000000000000000000000000000000000000000000000000000000000000000000001000000010100010101047f0000012ddd00000000000000000000000000000000000000008d24b1b6c5f86af4b8fa3fc6396ceda6dd6745b1e242ca6db2e403df8ebe94d6c0f487a9d4d7abb1eb4c614f5c83f64d61538e52b1ac712b6f965837494674462e9f59a500000002005847f80d0000001976a914add27799695434616eb5e3082da1369de92a0c7588ac0084fac1997aed710f159035ec5f481c52f64c7c3800902f50090000001976a9144ff00c1437dfe8d85b6f90a67abe3fbf1de8742588ac00e8605e9e3cfa456cb73d486b062a62eef4c383f620ea8e077af2c1b4264b7d68e056e36e7384d437c8e98de49453338ba5f68789ed554ab9a0bfb0d8f5f94c340d1fe785e1dd3a1909b634a9ea602c050e735ece4c20679d010ee17044b74254bcfddb5be92dc9b89cbb537fa6ab8164a0fff342441408404296b0d042273d8942844312fdeb5661b0f04cf0975f59b9b63d21f851fa1e00000000f2052a0100000028abe0f5db3bd18aa99f68feea5aef8c5ef3cca3763cc04b4f167c4ed333df6b00"),
    // feature_masternode_shares.py line 458
    ("bf813e5304627a0d8865651afeb9d104518c7b757a1e492fa7a92825d3cae1d4", "0300010008718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb060000006a473044022029b284f1a92678034efc57b474c4a3c52b316e5ebe2534e84a4e794b3a83a6a4022051c3ffd8f8019489ec0aeb80146e19f6e04f155eb46688c7c2fbf48b9a2be4ce012102beb3162198eb1e2e24a2027c4d86e763b6d091563fbf48af097bee64103a2178ffffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb070000006a47304402206cbf9a3008efb05e0ac14a2a5e292d671c4680004d0e8f4b3bdbd93156224870022054df08de321ad3cc490b4a77bc6c47060d02f7ee5375295d72ab5156c82b120001210390e7c9f87253a0e8754b27fe8dc2213dcf75ff14abc93ccf38f3c019e3e5c56effffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb030000006a473044022002fb6781c4448de31eabaa229ff56b75b9e7d53526e2c7af07276a13fd032d0d02207695e4e4b2e8ecb8ea913afcff86cd8316e7719c38fd083f52337a24ff057a5701210341a124196e75701477f3ff032559253373566fc827bccd70903400a86c090084ffffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb010000006a4730440220518ac83aefb0a49568f32174ae3f8adbb03307f069e4b734a80ca84dd311144602200218b527142bf41e413c326705f6073f55ed536990670892bdd1d2871d33870f012103a7be7081b645eea0001c2816d654ceffb99b6ef091eb804315f4cac8091afdb3ffffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb050000006a473044022061260ebb149c4e5f7326dab84c4045d79c5d63a565e6fce7f5703b0beab7609002205925d5a4051079ba194598460a0c70281b794e6398110b90efdeb28c6ef91d4f01210252bef56dd1519cf892aea78eb60c8c12e02861f12650e74c7de5a7d0c6baaf9affffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb020000006a4730440220643823032deaa434f9403d51a4264e29a75d3c9ad6ffdbeb8ba2b34fc49e2c4402205ab48577106c1bbed653b60fcaee0819d9e86336a3d466f88e0fc168735dff56012102aa2f98dc4c7105bb0619d2df881e5a28357c29fbe00c6391e4ec35bb264317fcffffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb040000006a473044022059f693488aee0e91d77c76f772e9a452f429e823ea306e225cbc3e37594628c702206de784d7fbfd1327e2d62cf687035fac03ee448547e9c0f0913f5a88f7053897012102370609f2980de2243005a3a114e4d2f67ab6e8e2243a07f1228892db3fd2b8b2ffffffff718a93b98bbbdafddac6c5d5789c970385f9e96371409404ecfe1499b4f098cb080000006a473044022071dfa8185b9ad0c9a408d1089dd21b83158fce5719b1ba0468708ae6213227f002206ddde15ed5ba364e5513eb1352e2f60f88c517d6578f7612bc441720d98bf3f5012103f82e7c7933c64f4dde4578a806bd1d26cbc186500df03db760daf53d5c2c5ee3ffffffff0978cdf505000000001976a91400f97590773d01569fa155f7c27112dc0112fc1288ac78cdf505000000001976a914be1e2e2b0038ef1a3cee391ba7ad53f358c92c1488ac78cdf505000000001976a914ac6469e3f6834bfda5bf69337edd422746dab6ff88ac78cdf505000000001976a914e415787fe5cca878d2d2d4d8c62b1f2d6c8fd37288ac78cdf505000000001976a9141911a11925c87e8410ea496ba4c0443dbca5d95488ac78cdf505000000001976a91487ba3295021689972054cf36d1e1c167eaf4b1a588ac78cdf505000000001976a914900d8ee025b09a04e59582f5e5e0e42ebc5b778f88ac78cdf505000000001976a914187273b22ab9505377561afd948a8297f4d6a8cf88ac00e8764817000000070444534843755100000000fd4605030000000000000000000000000000000000000000000000000000000000000000000000000008000000010100010101047f0000012de20000000000000000000000000000000000000000a0051de2878b2fdc3074d372adc46189190184070c4174841fae6d1d3bc8346bff4dc83aa4707c14ce6a4ff897b83dc063614b58218c52aa006833dca34907ddef702d8fe204000800e40b54020000001976a9146e6c55150a2a7a03298b0f15cee13bf62067c4fe88ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac744f0c11c031704e5029b22bca8e0b033212e92f00e40b54020000001976a914836fc8a301096552ec69a94e2b76e39f75d48deb88ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788acd333fa96d6346039784d41af9199a4b9bd4de90600e40b54020000001976a914ea1f0a66a9ca78aee3fd9eb6721ba60fee114ba688ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788acce3d41413a04ec296f76945ced3399fc524aee3f00e40b54020000001976a91440f1b5b19fbb0966c86d923344af3046457a6ca188ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac7b0af491647895b75cd64cfebf80babf5834dab300e40b54020000001976a91438ae4e6283fd8a4e7066d43bb21dc782889d9c9988ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788acff9b9b1abb86cdf4a680cb6fc88cd6e9b5d0bc2a00e40b54020000001976a9145e040300c831d56611a3c10ab6a66d49862326b188ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788acc67fd55cfc39f0304026b22d40400cb2dbe2ae9d00e40b54020000001976a9149d3a6b20a07d182519e2c55e445d040c56b1a08d88ac1976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac5b2641bd15ded69a36284fdad3426e86726ba38300ac23fc0600000017a914d015a362e5cf69693545428baa6d7e78d423afcd871976a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac57daec530ff90bc8fa59ae33cfb5ad42c286fd0a1fa8770bd0c71b6d49e17050fd07c4a28e193607df4b927bd7bafd9e22a134ac002fb0291a26e48b02ff26bdcc9e7b5e73287f90ce707e700aca5b21e2cd76c8e51f7f1c6966fbe152fc94654d3aaf44dd9e7c1ae66b4eba21741dc28c699270872c5d929713f1e665355380abf9514e34e89ad60175df8b4d7d2529ce862f3f55651f68e370ec313cfcc049a86028340dab50c741db1949b5d3246c671800eea3b14451c1e0a80e677be39033608d8552657c399b6aad44984b9b71dd6fae0a16644e1fc80188b5220b54d78af0d2530ee5d0159107d3a60cdde7e645d223519613a98c1b699c9e56a14be366d3f447d6b5f96806bf291cc78454b8421d7a14672d027720b998d9835bbcbd9feb1c30a1fb1e014c11dd7a4c505905541bb4245bcd178d634903f93284784e86c3b4ac0ca469c58bfcb7bda76ed63ba73487e832441f967a201ba64f41f1f5c872d8b0a06bf5cdcbc69663a9f5ca64cc636c76bbbb35f2a0f339c3e6a7ed34ca8e66e74167b3e8d57b5ed5366d0588f062228134b0172350f8200518a26077163a1866af2716100f52557c68e9578af3fad7e7c40504d806129619bf96b551448dc3e817bbf0d7210710a898b0e0213a037f2486c2907c329a5720c007d56099def855c53efa3111e54136e9d1cfa12e20085fb8883fae6113e93f1cb7ce8e786a4032b8f988cbebb8b4529c35b5f0ab0017e9580a586c824d49c86400000000ca9a3b00000000b0a3ffbf4a4e7621939cf95afece26555bcf0648e2d6f3ae983334c9879d7f8a00"),
    // feature_masternode_shares.py line 1358
    ("7cf73bfa24c05f3ef39b4c365366a0622c72a4de43ec8c18adfefa246be70ae7", "0300010009d1f1b3603ec12c1f971d9baa14c2c34281fe13ec21d8aca5f6e6e5467bcf4015000000006a47304402207eade9c58fc018bfa38aef636aa00378fb121acd8da3fe66d323e477b10433cc022016542ab1c0dac0a5f90c2b2a469e8ae6355978c6e1aa85553e187d1e6dedc78c0121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffffd0519e7879c443371aee1bccbf4680bcccb93003944e7d3f5a4601e760cefca2000000006a47304402200897ee0e3d9942e2813c8a2b895d7574dd1248b5966c0d1523b32967d05ad30302204097e0b4f07e0466f31c7023fa030a765c28ac4f719e1aa8eaf57c2ae93bc1450121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0fefffffff5e2f69628aa31e91612a24a054596886fe124fa85d187e06663dcc4ecabd8ba000000006a473044022020ee9ae5204f52daddb32461334b90a734ee77a36e5d97c2ab72da253335473b022057f259b2cb058fec459387c54d67829b1c47abbd2fdf89c28b7d8aa648a97a160121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffffa99a5fb12b8f2f262db6720e75bab893cfc24961db1b28c451738e9056a7e1d1000000006a473044022037cfe26ba2b1758ecbd83dc1e02f917b55b7ce20f460396c93774d5e0e0a98470220796fca698b14bf451fdf64fbc4391d2822bb6f7308df339334eda2c40c3593710121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffff9f8ae5ce53cdb384958ba98298ae6937e3a061379043f9ee57b23d5d8af3bdd4000000006a47304402205a864017c6018bf979c421921e0cd9bb952e1514b2c0753236f82caeb8fb369502202dde9503f4328f3ca6bf74ae4ea42ea9d25cc631e9323510d1e92de9b1cf83420121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffffe31f7906c797ed49318b5aac5e2e8151abb99a6917f2539aab4135c8e26fcfdb000000006a47304402202f65fd7bb6a4474d8308eb25a7f60c54c849075840556a6f99b703a564ee10aa02207aae54dcb82cf267b63b99b9942820c16a4b4d8f9414c652c038453e9a06cee10121038af19f35924e37ad7c3c8045d1e19b9b90b7310e08b892e620c253a102fe49f0feffffff7385d18bddf2c90c5b2525557cca7870c9a62deaf1bee99d9940a30a127e33ef000000006a473044022076500acd66bc029b6201444460d0fdf1adf65acc3fffd370b83e477824a5763502207fa4e4989d25890153ac70bbd9346ffb11e85edd7f7d4e264c3113faae0f5529012103d2316cb9fe06c78518b0fe4fdf6ab2675f1c68b29a4e409f5df2aac695f2770dfeffffff7385d18bddf2c90c5b2525557cca7870c9a62deaf1bee99d9940a30a127e33ef010000006a47304402205d81f759651970ce3b2047db6756c810d4999b32e5fc8b5c1c0dcbf1b3c8807e02202d48fb710a9c9ecafac68e9089a204ecac21e4077c67e21409f31389dfb91a78012103640922d6c301cf0694fb8f19ca609924d01cb36a772b89cbe068da73741638cafeffffff9cd8d2686d5885ba1e3765d8dc7e82edebd64e852d245e7c46dac506ea80efff000000006a473044022071e95a5e72dcf5cc75c49cd323ace8f55c5b67291345e46db059e1b1911e3c2b022060df64edc291e111cd1487b8e001ddea0b2b5f0c6b61daeab2cfa0134c744f38012102871bee1ba20b1a8aee9e52a6ef3f8cb1a593a73b00f0d3f1ee0543d9d8c69e1afeffffff02a9160800000000001976a914efb6d8fac2ad8d20ea23fceaa09a7d6a18fdc2c888ac00a0db215d000000070444534843755100000000fdda01030001000000000000000000000000000000000000000000000000000000000000000000000001000000010300010101047f0000012de501010101047f00000131cd02010101047f00000135b50000000000000000000000000000000000000000a6b9ec666acff86c94aa1ef4f907c6b13c87113af970ab2cb662169930eae830533b45c663e0604b669cb298b31865b22fbf9afb45e031451e06f7ab0164fc0b9d1197080000000200b864d9450000001976a914e4bfda1f1ea786645110e10bea91fde266e84ee388ac00e6352ddbbc903c71b33a328df325593f200c0b8700e87648170000001976a9143bed3c650fcba45a7a9eeab4873eebca7646e14888ac00e0395093ad7ced8e70e47fb9993502d5fc0a82921ff424422bf85a319dce3a4507c34d971afc38ff04048130c899416c1b3b07135c3bd3cd8a84414bf90fda754401d6c78adac859bcf6f7fd78633c66f9132791711fe6b1e72121e8bb4f47ff6d90be2df3ec8a6411747fa47749c9e7633b8575139d51dfeb71a27ac82a5488835c5d01e4d90dc2d1658c805dd1e32f8092d6bb2e461e00000000f2052a010000002ddb952e530c328afec8c9bb38cb99d9fadab2446e0f87d2b470eaa4ed033d12e52d00000000000000000000000000000000000000"),
  ];

  /// The payload of regtest transaction `txid`.
  fn regtest(txid: &str) -> ProRegTx {
    let (txid, raw) = REGTEST.into_iter().find(|(t, _)| *t == txid).unwrap();
    check_sptx_raw(&vec_from_hex(raw), txid)
  }

  #[rstest]
  #[case::payout_shares_119(REGTEST[0])]
  #[case::evo_shares_activation_129(REGTEST[1])]
  #[case::masternode_shares_95(REGTEST[2])]
  #[case::masternode_shares_458(REGTEST[3])]
  #[case::masternode_shares_1358(REGTEST[4])]
  fn regtest_vectors(#[case] vector: (&str, &str)) {
    let (txid, raw) = vector;
    assert_json_rt(&check_sptx_raw::<ProRegTx>(&vec_from_hex(raw), txid));
  }

  /// A share's `amount`, `refundScript`, `rewardScript` and `ownerAddress`, as
  /// `decoderawtransaction` reports them.
  type ReferenceShare = (i64, &'static str, &'static str, &'static str);

  /// The two shares of `be0bcc47`, whose reward scripts the payload leaves
  /// empty, so the reference reports the refund scripts.
  const SHARES_BE0BCC47: [ReferenceShare; 2] = [
    (
      60_000_000_000,
      "76a914add27799695434616eb5e3082da1369de92a0c7588ac",
      "76a914add27799695434616eb5e3082da1369de92a0c7588ac",
      "yYSaSNfBxK2wG4jqMsxDcXMhJBNVqgsuzZ",
    ),
    (
      40_000_000_000,
      "76a9144ff00c1437dfe8d85b6f90a67abe3fbf1de8742588ac",
      "76a9144ff00c1437dfe8d85b6f90a67abe3fbf1de8742588ac",
      "yhW94atMjMPdhE9ZgfFQ3BwvsQzgCvPGph",
    ),
  ];

  /// The eight shares of `bf813e53`, each with its own reward script, and
  /// the last refunded to a script hash.
  const SHARES_BF813E53: [ReferenceShare; 8] = [
    (
      10_000_000_000,
      "76a9146e6c55150a2a7a03298b0f15cee13bf62067c4fe88ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yWvRvkJPdE2AZjHstnZWQDohUtmz7dHJp7",
    ),
    (
      10_000_000_000,
      "76a914836fc8a301096552ec69a94e2b76e39f75d48deb88ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yfaBhEXeqHjjwNnhAWsxagAhaF73rG2H2P",
    ),
    (
      10_000_000_000,
      "76a914ea1f0a66a9ca78aee3fd9eb6721ba60fee114ba688ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yf7wRnVz8URtMHdEnf5ZSHhZ5x1qmLWo4n",
    ),
    (
      10_000_000_000,
      "76a91440f1b5b19fbb0966c86d923344af3046457a6ca188ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yXY35zJcLBMe9GxroAqQ8gV9MQDyD4Boir",
    ),
    (
      10_000_000_000,
      "76a91438ae4e6283fd8a4e7066d43bb21dc782889d9c9988ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yjcyZogWadDZk5gvD7oYffvbNW64poFtV6",
    ),
    (
      10_000_000_000,
      "76a9145e040300c831d56611a3c10ab6a66d49862326b188ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yeR1nD6MS1sBzoj6mt6gcoeFW8Eq5hQyeW",
    ),
    (
      10_000_000_000,
      "76a9149d3a6b20a07d182519e2c55e445d040c56b1a08d88ac",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yUdQAnfQauG7YjGsLvYU59sY36t23arGJz",
    ),
    (
      30_000_000_000,
      "a914d015a362e5cf69693545428baa6d7e78d423afcd87",
      "76a914755c798132ad433dc1b37fecd792f8acd7c1cf4788ac",
      "yUKytwQjcEw1RsCdxV3nGzMHg1zxdZ9Qr9",
    ),
  ];

  /// The share table and early terms that `decoderawtransaction` of the
  /// reference implementation at v24.0.0-rc.5 reports for a two-share and
  /// an eight-share registration, in share order.
  ///
  /// The reference reports the refund script as the reward script where the
  /// payload leaves the reward script empty.
  #[rstest]
  #[case::masternode_shares_95(REGTEST[2].0, 30, 5_000_000_000, &SHARES_BE0BCC47)]
  #[case::masternode_shares_458(REGTEST[3].0, 100, 1_000_000_000, &SHARES_BF813E53)]
  fn reference_shares(
    #[case] txid: &str,
    #[case] early_period_blocks: u32,
    #[case] early_penalty: i64,
    #[case] want: &[ReferenceShare],
  ) {
    let ptx = regtest(txid);
    assert_eq!(ptx.early_period_blocks, early_period_blocks, "earlyPeriodBlocks");
    assert_eq!(ptx.early_penalty, early_penalty, "earlyPenalty");
    let hex = |script: &ScriptPubKeyBuf| script.as_bytes().to_lower_hex_string();
    let got: Vec<(i64, String, String, String)> = ptx
      .shares
      .iter()
      .map(|share| {
        let refund = share.script_refund();
        let reward = share.script_reward();
        let reward = if reward.as_bytes().is_empty() { refund } else { reward };
        let owner = share.key_id_owner().to_base58c(Network::Regtest.addr().pubkey_addr);
        (share.amount(), hex(refund), hex(reward), owner)
      })
      .collect();
    let want: Vec<(i64, String, String, String)> = want
      .iter()
      .map(|&(amount, refund, reward, owner)| (amount, refund.into(), reward.into(), owner.into()))
      .collect();
    assert_eq!(got, want, "shares");
  }

  /// A testnet registration with one payout.
  fn registration() -> ProRegTx {
    entry("13ccca675ed8a8a788693f46191e7237e2896701ede3058c20263e1b2343923d")
  }

  /// A regtest registration with two shares.
  fn shared() -> ProRegTx {
    regtest("be0bcc4773f4510a7a3afdfd18e7758f007c3ff1eb57c3c7a500620c13a05b9c")
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
    ProTxInvalid::PayoutVersionMismatch { version: ProTxVersion::CoreV24 }
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
  #[case::operator_reward_before_null_platform_node_id(
    entry("2770d2493755b59b3426474b2a18eb5c34df636530ae8059aa1fe4b22ce47c3c"),
    |ptx: &mut ProRegTx| {
      ptx.platform_node_id = Some(PlatformNodeId::default());
      ptx.operator_reward = MAX_OPERATOR_REWARD + 1;
    },
    ProTxInvalid::OperatorRewardTooHigh { reward: MAX_OPERATOR_REWARD + 1 }
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
    let ptx = regtest("e069aa21a4c70c3cfec548d2fb99004207145cae53c400ae319626c966f471c8");
    let key = PubKeyHash::from_lendian(arr_from_hex("aa20a04ead2af1a823293452a32c6f5b33caccaa"));
    assert_eq!(ptx.payouts.len(), 2);
    assert_eq!(ptx.verify(&key, Network::Regtest.addr()), None);
  }
}
