//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use super::bls::{self, protx_bls_scheme, protx_source};
use super::shares::{self, PayoutShare};
use super::{check_version, is_known_protx_version, InputsHash, ProTxInvalid, PROTX_VERSION_EXT_ADDR};
use crate::prelude::*;
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::BlsLazyPk;
use dash_script::{PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_type, Checkable};

use core::fmt;

/// ProUpRegTx -- update registrar keys (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (owner payouts)
///
/// `script_payout` is empty from v3 and `payouts` below it, as in Core.
#[derive(Clone, Debug, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ProUpRegTxSerde", from = "ProUpRegTxSerde"))]
pub struct ProUpRegTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  /// Operator BLS public key, decoded on first use under the version's
  /// scheme (legacy for v1). It encodes as Core serializes a key in use,
  /// under the version's scheme at encoding, and as zeros when invalid,
  /// whether or not it was used before.
  pub pub_key_operator: BlsLazyPk,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Payout script (below v3).
  pub script_payout: ScriptPubKeyBuf,
  /// Owner payouts (v3).
  pub payouts: Vec<PayoutShare>,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Owner ECDSA signature (variable-length).
  pub vch_sig: Vec<u8>,
}

impl_type!(ProUpRegTx);

/// The serde form of [`ProUpRegTx`], with the operator key as raw bytes.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct ProUpRegTxSerde {
  version: u16,
  pro_tx_hash: TxHash,
  mode: u16,
  #[serde(with = "dash_types::serialize::hex")]
  pub_key_operator: [u8; dash_pkc::bls::BLS_PK_LEN],
  key_id_voting: PubKeyHash,
  script_payout: ScriptPubKeyBuf,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  payouts: Vec<PayoutShare>,
  inputs_hash: InputsHash,
  #[serde(with = "dash_types::serialize::hex")]
  vch_sig: Vec<u8>,
}

impl BaseCodec for ProUpRegTx {
  /// Decodes a payload of a known version.
  ///
  /// Core reads only the version of an unknown one, which
  /// [`SpecialPayload::decode`](super::SpecialPayload::decode) reports.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = check_version(u16::decode(data)?)?;
    let pro_tx_hash = TxHash::decode(data)?;
    let mode = u16::decode(data)?;
    let pub_key_operator = bls::read_lazy(data, protx_source(version))?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let (script_payout, payouts) = if version >= PROTX_VERSION_EXT_ADDR {
      (ScriptPubKeyBuf::new(), shares::read_list(data)?)
    } else {
      (ScriptPubKeyBuf::decode(data)?, Vec::new())
    };
    Ok(Self {
      version,
      pro_tx_hash,
      mode,
      pub_key_operator,
      key_id_voting,
      script_payout,
      payouts,
      inputs_hash: InputsHash::decode(data)?,
      vch_sig: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.mode.encode(buf);
    bls::write_lazy(&self.pub_key_operator, protx_bls_scheme(self.version), buf);
    self.key_id_voting.encode(buf);
    if self.version >= PROTX_VERSION_EXT_ADDR {
      shares::write_list(&self.payouts, buf);
    } else {
      self.script_payout.encode(buf);
    }
    self.inputs_hash.encode(buf);
    self.vch_sig.encode(buf);
  }
}

/// Part of Core's `IsTriviallyValid`, without chain context. The v3 payout
/// list rules (`IsPayoutListTriviallyValid`) are dash-evo's; of the payout
/// rules, this checks the scripts.
impl Checkable for ProUpRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if !is_known_protx_version(self.version) {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    if !self.pub_key_operator.get().is_valid() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    let scripts: Vec<&[u8]> = if self.version >= PROTX_VERSION_EXT_ADDR {
      self.payouts.iter().map(|p| p.script_payout.as_bytes()).collect()
    } else {
      vec![self.script_payout.as_bytes()]
    };
    for script in scripts {
      if !matches!(
        Recipient::from_script(script),
        Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))
      ) {
        return Some(ProTxInvalid::BadPayoutScript);
      }
    }

    None
  }
}

hash_impl!(ProUpRegTx);

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version)
  }
}

#[cfg(feature = "serde")]
impl From<ProUpRegTx> for ProUpRegTxSerde {
  fn from(tx: ProUpRegTx) -> Self {
    Self {
      version: tx.version,
      pro_tx_hash: tx.pro_tx_hash,
      mode: tx.mode,
      pub_key_operator: bls::lazy_bytes(&tx.pub_key_operator, protx_bls_scheme(tx.version)),
      key_id_voting: tx.key_id_voting,
      script_payout: tx.script_payout,
      payouts: tx.payouts,
      inputs_hash: tx.inputs_hash,
      vch_sig: tx.vch_sig,
    }
  }
}

#[cfg(feature = "serde")]
impl From<ProUpRegTxSerde> for ProUpRegTx {
  fn from(raw: ProUpRegTxSerde) -> Self {
    Self {
      version: raw.version,
      pro_tx_hash: raw.pro_tx_hash,
      mode: raw.mode,
      pub_key_operator: BlsLazyPk::from_bytes(&raw.pub_key_operator, protx_source(raw.version)),
      key_id_voting: raw.key_id_voting,
      script_payout: raw.script_payout,
      payouts: raw.payouts,
      inputs_hash: raw.inputs_hash,
      vch_sig: raw.vch_sig,
    }
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proupregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let items = corpus.entries::<ProUpRegTx>("proupregtx", check_sptx);
    assert_serde_rt("proupregtx", &items);
  }
}
