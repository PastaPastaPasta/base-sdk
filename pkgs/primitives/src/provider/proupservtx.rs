//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::proregtx::check_platform_fields;
use super::{OperatorSig, ProTxVersion};
use crate::codec::impl_payload;
use crate::provider::PlatformNodeId;
use crate::sptx::{check_sptx_netinfo, InputsHash, MnType, ProTxInvalid};
use crate::types::{NITrait, NetInfo, NetInfoV1, NetInfoV2, ServiceV1};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::{type_id::TypeId, Checkable, Numeric};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
///
/// - v1: LegacyBLS (no mn_type field)
/// - v2: BasicBLS (adds mn_type)
/// - v3: ExtAddr (extended network info)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpServTx {
  /// Payload version.
  pub version: ProTxVersion,
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
  #[cfg_attr(feature = "serde", serde(rename = "platformP2PPort"))]
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  pub platform_http_port: Option<u16>,
  /// Operator BLS signature.
  pub sig: OperatorSig,
}

impl_payload!(ProUpServTx);

impl BaseCodec for ProUpServTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = ProTxVersion::decode(data)?;

    let mn_type = if version >= ProTxVersion::BasicBls {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };

    let pro_tx_hash = TxHash::decode(data)?;
    let net_info = if version >= ProTxVersion::ExtAddr {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1(ServiceV1::decode(data)?))
    };
    let script_operator_payout = ScriptPubKeyBuf::decode(data)?;
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
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: OperatorSig::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    if self.version >= ProTxVersion::BasicBls {
      self.mn_type.to_base().encode(buf);
    }
    self.pro_tx_hash.encode(buf);
    // Branch on version to match the decode path. Validation
    // guarantees the variant matches the version.
    if self.version >= ProTxVersion::ExtAddr {
      if let NetInfo::Extended(ext) = &self.net_info {
        ext.encode(buf);
      }
    } else if let NetInfo::Legacy(svc) = &self.net_info {
      svc.encode(buf);
    }
    self.script_operator_payout.encode(buf);
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

impl Checkable for ProUpServTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }

    if self.mn_type == MnType::Evo && self.version < ProTxVersion::BasicBls {
      return Some(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= ProTxVersion::ExtAddr) {
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

impl fmt::Display for ProUpServTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "ProUpServTx {{ v{}, mn_type: {} }}",
      self.version.to_base(),
      self.mn_type,
    )
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
