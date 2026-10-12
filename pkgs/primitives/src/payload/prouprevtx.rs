//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use super::bls::{self, protx_bls_scheme, protx_source};
use super::{InputsHash, ProTxInvalid};
use crate::support::RevocationReason;
use crate::{hash_impl, TxHash};

use dash_pkc::bls::BlsEagerSig;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_type, Checkable};

use core::fmt;

/// ProUpRevTx -- revoke masternode (type 4).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (same fields)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ProUpRevTxSerde", try_from = "ProUpRevTxSerde"))]
pub struct ProUpRevTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Revocation reason.
  pub reason: RevocationReason,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Operator BLS signature under the version's scheme (legacy for v1).
  ///
  /// Core verifies it under its process-wide flag instead.
  pub sig: BlsEagerSig,
}

impl_type!(ProUpRevTx);

/// The serde form of [`ProUpRevTx`], with the signature as raw bytes.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct ProUpRevTxSerde {
  version: u16,
  pro_tx_hash: TxHash,
  reason: RevocationReason,
  inputs_hash: InputsHash,
  #[serde(with = "dash_types::serialize::hex")]
  sig: [u8; dash_pkc::bls::BLS_SIG_LEN],
}

impl BaseCodec for ProUpRevTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    Ok(Self {
      version,
      pro_tx_hash: TxHash::decode(data)?,
      reason: RevocationReason::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      sig: bls::read_eager(data, protx_source(version))?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.reason.encode(buf);
    self.inputs_hash.encode(buf);
    self.sig.to_bytes(protx_bls_scheme(self.version)).encode(buf);
  }
}

impl Checkable for ProUpRevTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if matches!(self.reason, RevocationReason::Unknown(_)) {
      return Some(ProTxInvalid::BadReason { reason: self.reason });
    }

    None
  }
}

hash_impl!(ProUpRevTx);

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version)
  }
}

#[cfg(feature = "serde")]
impl From<ProUpRevTx> for ProUpRevTxSerde {
  fn from(tx: ProUpRevTx) -> Self {
    Self {
      version: tx.version,
      pro_tx_hash: tx.pro_tx_hash,
      reason: tx.reason,
      inputs_hash: tx.inputs_hash,
      sig: tx.sig.to_bytes(protx_bls_scheme(tx.version)),
    }
  }
}

#[cfg(feature = "serde")]
impl TryFrom<ProUpRevTxSerde> for ProUpRevTx {
  type Error = DecodeError;

  fn try_from(raw: ProUpRevTxSerde) -> Result<Self, Self::Error> {
    Ok(Self {
      version: raw.version,
      pro_tx_hash: raw.pro_tx_hash,
      reason: raw.reason,
      inputs_hash: raw.inputs_hash,
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
  fn corpus_prouprevtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prouprevtx");
    let items = corpus.entries::<ProUpRevTx>("prouprevtx", check_sptx);
    assert_serde_rt("prouprevtx", &items);
  }
}
