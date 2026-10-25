//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use super::share::{check_payout_version, check_payouts, MAX_REWARD};
use super::{OwnerSig, PayoutShare, ProTxVersion};
use crate::codec::{decode_list, encode_list, impl_payload};
use crate::prelude::*;
use crate::sign::{unsigned_digest, verify_compact};
use crate::sptx::{InputsHash, ProTxInvalid};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::BlsPkBytes;
use dash_pkc::ecdsa::{EcdsaError, ECDSA_REC_SIG_LEN};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, Signable};
use getset::{CopyGetters, Getters};

use core::fmt;

/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (owner payouts)
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpRegTx {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: ProTxVersion,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Reserved, always 0.
  #[getset(get_copy = "pub")]
  mode: u16,
  /// Operator BLS public key (48 bytes).
  #[getset(get_copy = "pub")]
  pub_key_operator: BlsPkBytes,
  /// Voting key id (20 bytes).
  #[getset(get_copy = "pub")]
  key_id_voting: PubKeyHash,
  /// Payout script (version < 3 only).
  #[getset(get = "pub")]
  script_payout: ScriptPubKeyBuf,
  /// Owner payouts (version 3).
  #[getset(get = "pub")]
  payouts: Vec<PayoutShare>,
  /// Hash of all inputs.
  #[getset(get_copy = "pub")]
  inputs_hash: InputsHash,
  /// Owner ECDSA signature.
  #[cfg_attr(feature = "serde", serde(rename = "vchSig"))]
  #[getset(get = "pub")]
  sig: OwnerSig,
}

impl_payload!(ProUpRegTx);

impl BaseCodec for ProUpRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = ProTxVersion::decode(data)?;
    let pro_tx_hash = TxHash::decode(data)?;
    let mode = u16::decode(data)?;
    let pub_key_operator = BlsPkBytes::decode(data)?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let (script_payout, payouts) = if version >= ProTxVersion::ExtAddr {
      (ScriptPubKeyBuf::new(), decode_list(data)?)
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
      sig: OwnerSig::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.mode.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    if self.version >= ProTxVersion::ExtAddr {
      encode_list(&self.payouts, buf);
    } else {
      self.script_payout.encode(buf);
    }
    self.inputs_hash.encode(buf);
    self.sig.encode(buf);
  }
}

impl Signable for ProUpRegTx {
  type Key = PubKeyHash;
  type Context = ();
  type Error = EcdsaError;

  fn payload(&self, _ctx: &()) -> Vec<u8> {
    unsigned_digest(self, &self.sig).to_vec()
  }

  fn set_signature(&mut self, sig: &[u8], key: &PubKeyHash, _ctx: &()) -> Result<(), EcdsaError> {
    let sig = <[u8; ECDSA_REC_SIG_LEN]>::try_from(sig).map_err(|_| EcdsaError::InvalidSignature)?;
    verify_compact(&self.payload(&()), &sig, key)?;
    self.sig = OwnerSig::new(sig);
    Ok(())
  }

  fn reset_signature(&mut self) {
    self.sig = OwnerSig::default();
  }

  fn verify(&self, key: &PubKeyHash, _ctx: &()) -> Option<EcdsaError> {
    let sig = self.sig.as_bytes().ok_or(EcdsaError::InvalidSignature);
    sig.and_then(|sig| verify_compact(&self.payload(&()), sig, key)).err()
  }
}

impl Checkable for ProUpRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }
    if let Some(e) = check_payout_version(self.version, &self.script_payout, &self.payouts) {
      return Some(e);
    }

    if self.pub_key_operator.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    if self.version >= ProTxVersion::ExtAddr {
      return check_payouts(&self.payouts, None, &self.key_id_voting);
    }
    let payout = PayoutShare::new(self.script_payout.clone(), MAX_REWARD);
    check_payouts(&[payout], None, &self.key_id_voting)
  }
}

hash_impl!(ProUpRegTx);

impl ProUpRegTx {
  /// Constructs an unsigned payload. The signature is set through
  /// [`Signable::set_signature`].
  pub fn new(
    version: ProTxVersion,
    pro_tx_hash: TxHash,
    mode: u16,
    pub_key_operator: BlsPkBytes,
    key_id_voting: PubKeyHash,
    script_payout: ScriptPubKeyBuf,
    payouts: Vec<PayoutShare>,
    inputs_hash: InputsHash,
  ) -> Self {
    Self {
      version,
      pro_tx_hash,
      mode,
      pub_key_operator,
      key_id_voting,
      script_payout,
      payouts,
      inputs_hash,
      sig: OwnerSig::default(),
    }
  }
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version.to_base())
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::provider::share::tests::script;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use dash_script::Recipient;
  use rstest::rstest;

  #[rstest]
  fn corpus_proupregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let items = corpus.entries::<ProUpRegTx>("proupregtx", check_sptx);
    assert_serde_rt("proupregtx", &items);
  }

  /// A version 2 payload from the chain.
  fn basic_bls() -> ProUpRegTx {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let entries = corpus.entries::<ProUpRegTx>("proupregtx", |_, _, _| {});
    entries
      .into_values()
      .find(|ptx| ptx.version == ProTxVersion::BasicBls)
      .unwrap()
  }

  /// A regtest update with eight payouts.
  fn update() -> ProUpRegTx {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let mut entries = corpus.entries::<ProUpRegTx>("proupregtx", |_, _, _| {});
    entries
      .remove("e7cb375dc4fbb47d60490f298538d8f48adc11e9af8619963d39923234cac08e")
      .unwrap()
  }

  /// The first payout of `ptx` paid to `key` instead.
  fn first_to(ptx: &mut ProUpRegTx, key: PubKeyHash) {
    ptx.payouts[0] = PayoutShare::new(script(Recipient::PubKeyHash(key)), ptx.payouts[0].reward());
  }

  /// Payouts are checked with the voting key and without an owner key.
  #[rstest]
  #[case::payout_to_voting(
    update(),
    |ptx: &mut ProUpRegTx| first_to(ptx, ptx.key_id_voting),
    Some(ProTxInvalid::PayoutKeyReuse)
  )]
  #[case::payout_to_null_key(update(), |ptx: &mut ProUpRegTx| first_to(ptx, PubKeyHash::default()), None)]
  #[case::v2_payout_to_voting(
    basic_bls(),
    |ptx: &mut ProUpRegTx| ptx.script_payout = script(Recipient::PubKeyHash(ptx.key_id_voting)),
    Some(ProTxInvalid::PayoutKeyReuse)
  )]
  #[case::payout_version(
    update(),
    |ptx: &mut ProUpRegTx| ptx.script_payout = ptx.payouts[0].script_payout().clone(),
    Some(ProTxInvalid::PayoutVersionMismatch { version: ProTxVersion::ExtAddr })
  )]
  fn check(#[case] mut ptx: ProUpRegTx, #[case] edit: fn(&mut ProUpRegTx), #[case] expected: Option<ProTxInvalid>) {
    assert_eq!(ptx.check(), None);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
