//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use super::{OwnerSig, ProTxVersion};
use crate::codec::codec_payload;
use crate::prelude::*;
use crate::sign::{unsigned_digest, verify_compact};
use crate::sptx::{InputsHash, ProTxInvalid};
use crate::TxHash;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::BlsPkBytes;
use dash_pkc::ecdsa::{EcdsaError, ECDSA_REC_SIG_LEN};
use dash_script::{PubKeyHash, Recipient};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, Signable};

use core::fmt;

codec_payload! { @no_new
/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpRegTx {
  /// Payload version.
  pub version: ProTxVersion,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPkBytes,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Payout script.
  pub script_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Owner ECDSA signature.
  pub vch_sig: OwnerSig,
}
}

impl Signable for ProUpRegTx {
  type Key = PubKeyHash;
  type Context = ();
  type Error = EcdsaError;

  fn payload(&self, _ctx: &()) -> Vec<u8> {
    unsigned_digest(self, &self.vch_sig).to_vec()
  }

  fn set_signature(&mut self, sig: &[u8], key: &PubKeyHash, _ctx: &()) -> Result<(), EcdsaError> {
    let sig = <[u8; ECDSA_REC_SIG_LEN]>::try_from(sig).map_err(|_| EcdsaError::InvalidSignature)?;
    verify_compact(&self.payload(&()), &sig, key)?;
    self.vch_sig = OwnerSig::new(sig);
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.vch_sig = OwnerSig::default();
  }

  fn verify(&self, key: &PubKeyHash, _ctx: &()) -> Option<EcdsaError> {
    let sig = self.vch_sig.as_bytes().ok_or(EcdsaError::InvalidSignature);
    sig.and_then(|sig| verify_compact(&self.payload(&()), sig, key)).err()
  }
}

impl Checkable for ProUpRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    if self.pub_key_operator.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    if !matches!(
      Recipient::from_script(payout),
      Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))
    ) {
      return Some(ProTxInvalid::BadPayoutScript);
    }

    None
  }
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version.to_base())
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
