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
    let (script_payout, payouts) = if version >= ProTxVersion::CoreV24 {
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
    if self.version >= ProTxVersion::CoreV24 {
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

    if self.version >= ProTxVersion::CoreV24 {
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

  use dash_dev::{assert_json_rt, assert_serde_rt, check_sptx, check_sptx_raw, vec_from_hex, Corpus};
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

  /// Regtest transactions as txid and raw bytes, from functional tests of the
  /// reference implementation at v24.0.0-rc.4.
  /// `dash-cli -regtest decoderawtransaction <raw>` decodes each one.
  const REGTEST: [(&str, &str); 2] = [
    // feature_masternode_payout_shares.py line 194
    ("e7cb375dc4fbb47d60490f298538d8f48adc11e9af8619963d39923234cac08e", "03000300019f041fdf148b81b7ea7a6d6c414b75afa857661e815dc0ed9d1958d9fa7545aa000000006a4730440220159286c19b7540bb534aaae0f8ced63c23c1b16cb3b994a27edea17792d38e720220308a61fcd6f975a555b11fc98795b9c8dcb1a188fbefda07b8b795479244c24301210259b7fcb2ca6ca1b24a1513262dee6f3b30fc67044e46f297c56af8223e4986d0feffffff0189def505000000001976a9140e00d7c0f238858417090e0527d542936a1889a588ac00000000fdab010300c871f466c9269631ae00c453ae5c1407420099fbd248c5fe3c0cc7a421aa69e0000093ef271a050424cc43f4cbd80205efd3f12e54749c547c77ec50c0d7d3c115933495c0d99f24cd5a96f32fb9d6fd7c88b2638afa676c107be6e1cdac662a47f81df28d02081976a91483fb1994b50e4d20f0cf96ae606d7aec9a27977788ace2041976a914ba8f17d6219820fc9de9f5850e8ad036c8a9ec6788ace2041976a914209a0b7cf39822b598b6d7865c928e639a0ef5bf88ace2041976a914b5aeae0ed79153fc466aa6fa5dfb0f762eb817d388ace2041976a914b35f4bdaa349231e1a6b88ec47ecba8ceb38ad8788ace2041976a914707061e5c2b1a0b3000f7948a951943715cd1b7c88ace2041976a914125ec8d31851b3c3310141cb9b6f7ec98a6c157a88ace2041976a91460d201f0670519444718f94da6c112ab03402cb188ace20439c723cacdb83ad887bd484557bb804fe8efcd78be69fd1fb328c1f416106e31411f705e2357ae088f9df4ccc64059868adeaf00c2a28916082685b7e88c597aa6b92658d518404565928e671462fe218b3995054f01a1bcb59501bd6d2df51d7e4f"),
    // feature_evo_shares_activation.py line 123
    ("6e83b4a013340ed470b779afae8b53f008da3e4468e02c224c562a092fb9b053", "0300030001257779344411a54e95958ce70f7a192b305ce2a75ffc246e9fcd2fbc3a36aba1000000006a4730440220513455e3b8bb9ae257c74ad0e2561f5d2065891c7a7e71f3f566057146a6480c0220022b995c43f064171bf83d02f09bd2631025918adc215e1ea279486406369d49012102908f4af445644a9a29bbc06183b2510c5ab5f1cf4e8782218e4dd7952833408cfeffffff0131dff505000000001976a914337b254c34edc9271845cf4b972303d1332bea3388ac00000000fd0301030088f952c9eda948d0362645b3808972e3d6b0b9ed64f67af63671cf85d7cfe010000086b871543fc2e461bcdd7ab4e7b446ecbcb33077f9b8e55f11094e611dfd3446fef186f5d0d492b207466f948d481936d896e7bf99f351c25eec7aba3ab32862d44d5e83021976a914bd8e4dbd1b1f9c44d944f5f24ca067426fb6c44688ac70171976a914053e7456f8d43cfcc904a4c55c139e107e83d58788aca00f5cd54f67cc807668f1b5524b8904f4f97cdcfaf5e25717dc2562b73ece32f59741208a916d823f361b02218623d847b177567ca16ad4913d7d14911bcf1426c94fe06b191eca07d78b5f81a261e96380b2311a3a023ed7922709936bb2a2d1ad1a93"),
  ];

  /// The payload of regtest transaction `txid`.
  fn regtest(txid: &str) -> ProUpRegTx {
    let (txid, raw) = REGTEST.into_iter().find(|(t, _)| *t == txid).unwrap();
    check_sptx_raw(&vec_from_hex(raw), txid)
  }

  #[rstest]
  #[case::payout_shares_194(REGTEST[0])]
  #[case::evo_shares_activation_123(REGTEST[1])]
  fn regtest_vectors(#[case] vector: (&str, &str)) {
    let (txid, raw) = vector;
    assert_json_rt(&check_sptx_raw::<ProUpRegTx>(&vec_from_hex(raw), txid));
  }

  /// A regtest update with eight payouts.
  fn update() -> ProUpRegTx {
    regtest("e7cb375dc4fbb47d60490f298538d8f48adc11e9af8619963d39923234cac08e")
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
    Some(ProTxInvalid::PayoutVersionMismatch { version: ProTxVersion::CoreV24 })
  )]
  fn check(#[case] mut ptx: ProUpRegTx, #[case] edit: fn(&mut ProUpRegTx), #[case] expected: Option<ProTxInvalid>) {
    assert_eq!(ptx.check(), None);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
