//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::proregtx::check_platform_fields;
use super::sig::verify_operator;
use super::{write_net_info, OperatorSig, PlatformNodeId, ProTxVersion};
use crate::codec::impl_payload;
use crate::payload::bls::{self, protx_bls_scheme, protx_source};
use crate::prelude::*;
use crate::sign::sha256d;
use crate::sptx::{check_sptx_netinfo, InputsHash, MnType, ProTxInvalid};
use crate::types::{NITrait, NetInfo, NetInfoV1, NetInfoV2};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::{BlsEagerSig, BlsError, BlsPkBytes, BlsSigBytes, BlsValue, BLS_SIG_LEN};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::{type_id::TypeId, Checkable, Numeric, Signable};
use getset::{CopyGetters, Getters};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ProUpServTxSerde", try_from = "ProUpServTxSerde"))]
pub struct ProUpServTx {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: ProTxVersion,
  /// v2+ only; defaults to Regular for v1.
  #[getset(get_copy = "pub")]
  mn_type: MnType,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Legacy ServiceV1 or extended NetInfo.
  #[getset(get = "pub")]
  net_info: NetInfo,
  /// Operator payout script.
  #[getset(get = "pub")]
  script_operator_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  #[getset(get_copy = "pub")]
  inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  #[getset(get_copy = "pub")]
  platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  #[getset(get_copy = "pub")]
  platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  #[getset(get_copy = "pub")]
  platform_http_port: Option<u16>,
  /// Operator BLS signature under the version's scheme (legacy for v1).
  ///
  /// Core verifies it under its process-wide flag instead.
  #[getset(get = "pub")]
  sig: BlsEagerSig,
}

impl_payload!(ProUpServTx);

/// The serde form of [`ProUpServTx`], with the signature as raw bytes.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct ProUpServTxSerde {
  version: ProTxVersion,
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
  /// [`SpecialPayload::decode`](crate::SpecialPayload::decode) reports.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = ProTxVersion::decode(data)?;
    let mn_type = if version >= ProTxVersion::BasicBls {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };
    let pro_tx_hash = TxHash::decode(data)?;
    let net_info = if version >= ProTxVersion::CoreV24 {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1::decode(data)?)
    };
    let script_operator_payout = ScriptPubKeyBuf::decode(data)?;
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

/// The operator signs the SHA256d of [`ProUpServTx::sig_hash_bytes`] under the
/// version's scheme.
impl Signable for ProUpServTx {
  type Key = BlsPkBytes;
  type Context = ();
  type Error = BlsError;

  fn payload(&self, _ctx: &()) -> Vec<u8> {
    sha256d(&self.sig_hash_bytes()).to_vec()
  }

  fn set_signature(&mut self, sig: &[u8], key: &BlsPkBytes, _ctx: &()) -> Result<(), BlsError> {
    let sig = <[u8; BLS_SIG_LEN]>::try_from(sig).map_err(|_| BlsError::InvalidSignature)?;
    verify_operator(
      self.version,
      &self.payload(&()),
      &OperatorSig::new(BlsSigBytes::from_bytes(sig)),
      key,
    )?;
    self.sig = bls::eager_from(&sig, protx_source(self.version)).map_err(|_| BlsError::InvalidSignature)?;
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.sig = BlsEagerSig::new(BlsValue::invalid(), protx_bls_scheme(self.version));
  }

  fn verify(&self, key: &BlsPkBytes, _ctx: &()) -> Option<BlsError> {
    let sig = OperatorSig::new(BlsSigBytes::from_bytes(
      self.sig.to_bytes(protx_bls_scheme(self.version)),
    ));
    verify_operator(self.version, &self.payload(&()), &sig, key).err()
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
    if is_extended != (self.version >= ProTxVersion::CoreV24) {
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
  /// Constructs an unsigned payload, its signature invalid. The signature is
  /// set through [`Signable::set_signature`].
  pub fn new(
    version: ProTxVersion,
    mn_type: MnType,
    pro_tx_hash: TxHash,
    net_info: NetInfo,
    script_operator_payout: ScriptPubKeyBuf,
    inputs_hash: InputsHash,
    platform_node_id: Option<PlatformNodeId>,
    platform_p2p_port: Option<u16>,
    platform_http_port: Option<u16>,
  ) -> Self {
    Self {
      version,
      mn_type,
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: BlsEagerSig::new(BlsValue::invalid(), protx_bls_scheme(version)),
    }
  }

  /// The payload's `SER_GETHASH` serialization, which leaves out `sig`. The
  /// operator signs its SHA256d.
  pub fn sig_hash_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode_unsigned(&mut buf);
    buf
  }

  /// Every field but `sig`, as [`BaseCodec::encode`] writes them.
  fn encode_unsigned(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    if self.version >= ProTxVersion::BasicBls {
      self.mn_type.to_base().encode(buf);
    }
    self.pro_tx_hash.encode(buf);
    write_net_info(buf, &self.net_info, self.version);
    self.script_operator_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if self.mn_type == MnType::Evo {
      self.platform_node_id.unwrap_or_default().encode(buf);
      if self.version < ProTxVersion::CoreV24 {
        self.platform_p2p_port.unwrap_or(0).encode(buf);
        self.platform_http_port.unwrap_or(0).encode(buf);
      }
    }
  }
}

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
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::types::NIError;

  use dash_dev::{assert_serde_rt, check_sptx, check_sptx_except, Corpus};
  use rstest::rstest;

  /// The corpus entries from regtest, whose services are on local addresses.
  /// The reference implementation accepts them on regtest alone, and the
  /// check refuses them on every network.
  const REGTEST: [&str; 3] = [
    "369881c12aa676d0a9829cdc849df0c75e9729296883cbbdc3822f1e267c6368",
    "639f00f22f730daa3fb0bb09e250d3f5c486987c4fb48da42804908c015a1ef6",
    "1c4cee0257db158902bfdd4441c88f86e1dd53617156cb53ff3cc92d6caeef43",
  ];

  /// The check's refusal of the entries in [`REGTEST`].
  const LOCAL_ADDRESS: ProTxInvalid = ProTxInvalid::NetInfoInvalid {
    error: NIError::SpecialUse,
  };

  /// An Evo update with an extended NetInfo whose version is unsupported reads
  /// the version alone, and its next fields read from the byte after it.
  #[rstest]
  #[case::zero(0)]
  #[case::future(2)]
  fn unsupported_net_info_version(#[case] version: u8) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let mut payload = corpus.entries::<ProUpServTx>("proupservtx", |_, _, _| {})
      ["369881c12aa676d0a9829cdc849df0c75e9729296883cbbdc3822f1e267c6368"]
      .clone();
    let mut raw = Vec::new();
    payload.encode(&mut raw);
    // The version, type and ProTx hash come before the NetInfo.
    let start = 2 + 2 + 32;
    let mut rest = &raw[start..];
    assert_eq!(
      NetInfoV2::decode(&mut rest).map(NetInfo::Extended),
      Ok(payload.net_info.clone())
    );
    let end = raw.len() - rest.len();
    raw.splice(start..end, [version]);
    payload.net_info = NetInfo::Extended(NetInfoV2::new(version, Vec::new()));

    let mut data = raw.as_slice();
    assert_eq!(ProUpServTx::decode(&mut data), Ok(payload.clone()));
    assert!(data.is_empty());
    let mut written = Vec::new();
    payload.encode(&mut written);
    assert_eq!(written, raw);
  }

  #[rstest]
  fn corpus_proupservtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let items = corpus.entries::<ProUpServTx>("proupservtx", |raw, details, label| {
      if REGTEST.contains(&label) {
        assert_eq!(
          check_sptx_except::<ProUpServTx>(raw, label, &[LOCAL_ADDRESS]),
          *details,
          "{label}"
        );
      } else {
        check_sptx(raw, details, label);
      }
    });
    assert!(
      REGTEST.iter().all(|label| items.contains_key(*label)),
      "a regtest label left the corpus"
    );
    assert_serde_rt("proupservtx", &items);
  }

  /// Checks on mainnet Evo update `e8812ae7`.
  #[rstest]
  #[case::null_platform_node_id(
    |ptx: &mut ProUpServTx| ptx.platform_node_id = Some(PlatformNodeId::default()),
    ProTxInvalid::NullPlatformNodeId
  )]
  fn check(#[case] edit: fn(&mut ProUpServTx), #[case] expected: ProTxInvalid) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let mut ptx = corpus
      .entries::<ProUpServTx>("proupservtx", |_, _, _| {})
      .remove("e8812ae795f44406cbdc70fc5ebe8e975180e8b28d7ab4eb0f7b3e9d66b1d62b")
      .unwrap();
    assert_eq!(ptx.check(), None);
    edit(&mut ptx);
    assert_eq!(ptx.check(), Some(expected));
  }
}
