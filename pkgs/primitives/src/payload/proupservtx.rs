//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::bls::{self, protx_bls_scheme, protx_source};
use super::{
  check_platform_fields, check_sptx_netinfo, check_version, is_known_protx_version, read_net_info,
  read_platform_fields, supported_version, write_net_info, write_platform_fields, InputsHash, MnType, ProTxInvalid,
  PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR,
};
use crate::payload::PlatformNodeId;
use crate::prelude::*;
use crate::types::{NITrait, NetInfo};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::BlsEagerSig;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::{impl_type, type_id::TypeId, Checkable, Numeric};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
///
/// - v1: LegacyBLS (no mn_type field)
/// - v2: BasicBLS (adds mn_type)
/// - v3: ExtAddr (extended network info)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ProUpServTxSerde", try_from = "ProUpServTxSerde"))]
pub struct ProUpServTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// v2+ only; defaults to Regular for v1.
  pub mn_type: MnType,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Legacy ServiceV1 or extended NetInfo.
  pub net_info: NetInfo,
  /// Operator payout script.
  pub script_operator_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  pub platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  pub platform_http_port: Option<u16>,
  /// Operator BLS signature under the version's scheme (legacy for v1).
  ///
  /// Core verifies it under its process-wide flag instead.
  pub sig: BlsEagerSig,
}

impl_type!(ProUpServTx);

/// The serde form of [`ProUpServTx`], with the signature as raw bytes.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct ProUpServTxSerde {
  version: u16,
  mn_type: MnType,
  pro_tx_hash: TxHash,
  net_info: NetInfo,
  script_operator_payout: ScriptPubKeyBuf,
  inputs_hash: InputsHash,
  platform_node_id: Option<PlatformNodeId>,
  #[serde(rename = "platformP2PPort")]
  platform_p2p_port: Option<u16>,
  #[serde(rename = "platformHTTPPort")]
  platform_http_port: Option<u16>,
  #[serde(with = "dash_types::serialize::hex")]
  sig: [u8; dash_pkc::bls::BLS_SIG_LEN],
}

impl BaseCodec for ProUpServTx {
  /// Decodes a payload of a known version.
  ///
  /// Core reads only the version of an unknown one, which
  /// [`SpecialPayload::decode`](super::SpecialPayload::decode) reports.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = check_version(u16::decode(data)?)?;
    let mn_type = if version >= PROTX_VERSION_BASIC_BLS {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };
    let pro_tx_hash = TxHash::decode(data)?;
    let net_info = read_net_info(data, version)?;
    let script_operator_payout = ScriptPubKeyBuf::decode(data)?;
    let inputs_hash = InputsHash::decode(data)?;
    let (platform_node_id, platform_p2p_port, platform_http_port) = read_platform_fields(data, mn_type, version)?;

    Ok(Self {
      version,
      mn_type,
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: bls::read_eager(data, protx_source(version))?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_unsigned(buf);
    self.sig.to_bytes(protx_bls_scheme(self.version)).encode(buf);
  }
}

impl Checkable for ProUpServTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if !is_known_protx_version(self.version) {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }

    if self.mn_type == MnType::Evo && self.version < PROTX_VERSION_BASIC_BLS {
      return Some(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= PROTX_VERSION_EXT_ADDR) {
      return Some(ProTxInvalid::NetInfoVersionMismatch);
    }

    match &self.net_info {
      NetInfo::Legacy(addr) => {
        if addr.is_empty() {
          return Some(ProTxInvalid::NetInfoEmpty);
        }
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

hash_impl!(ProUpServTx);

impl ProUpServTx {
  /// The payload's `SER_GETHASH` serialization, which leaves out `sig`. The
  /// operator signs its SHA256d.
  ///
  /// # Errors
  ///
  /// Unsupported versions are refused.
  pub fn sig_hash_bytes(&self) -> Result<Vec<u8>, ProTxInvalid> {
    supported_version(self.version)?;
    let mut buf = Vec::new();
    self.encode_unsigned(&mut buf);
    Ok(buf)
  }

  /// Every field but `sig`, as [`BaseCodec::encode`] writes them.
  fn encode_unsigned(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    if self.version >= PROTX_VERSION_BASIC_BLS {
      self.mn_type.to_base().encode(buf);
    }
    self.pro_tx_hash.encode(buf);
    write_net_info(buf, &self.net_info, self.version);
    self.script_operator_payout.encode(buf);
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

impl fmt::Display for ProUpServTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpServTx {{ v{}, mn_type: {} }}", self.version, self.mn_type,)
  }
}

#[cfg(feature = "serde")]
impl From<ProUpServTx> for ProUpServTxSerde {
  fn from(tx: ProUpServTx) -> Self {
    Self {
      version: tx.version,
      mn_type: tx.mn_type,
      pro_tx_hash: tx.pro_tx_hash,
      net_info: tx.net_info,
      script_operator_payout: tx.script_operator_payout,
      inputs_hash: tx.inputs_hash,
      platform_node_id: tx.platform_node_id,
      platform_p2p_port: tx.platform_p2p_port,
      platform_http_port: tx.platform_http_port,
      sig: tx.sig.to_bytes(protx_bls_scheme(tx.version)),
    }
  }
}

#[cfg(feature = "serde")]
impl TryFrom<ProUpServTxSerde> for ProUpServTx {
  type Error = DecodeError;

  fn try_from(raw: ProUpServTxSerde) -> Result<Self, Self::Error> {
    Ok(Self {
      version: raw.version,
      mn_type: raw.mn_type,
      pro_tx_hash: raw.pro_tx_hash,
      net_info: raw.net_info,
      script_operator_payout: raw.script_operator_payout,
      inputs_hash: raw.inputs_hash,
      platform_node_id: raw.platform_node_id,
      platform_p2p_port: raw.platform_p2p_port,
      platform_http_port: raw.platform_http_port,
      sig: bls::eager_from(&raw.sig, protx_source(raw.version))?,
    })
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proupservtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let items = corpus.entries::<ProUpServTx>("proupservtx", check_sptx);
    assert_serde_rt("proupservtx", &items);
  }
}
