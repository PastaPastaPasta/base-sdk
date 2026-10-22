//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash transaction with version/type packing and optional extra payload for
//! special transactions.

use crate::block::MAX_LEGACY_BLOCK_SIZE;
use crate::prelude::*;
use crate::sptx::{PayloadError, PayloadInvalid, QuorumHash, TxType};
use crate::{codec_type, hash_impl};

use bitcoin_hashes::sha256d;
use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin_units::SignedAmount;
use dash_num::make_hash;
use dash_pkc::bls::BlsSigBytes;
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_new, impl_type, Checkable, CompactSize, Hashable, Numeric};
use getset::{CopyGetters, Getters};

use core::fmt;

/// Maximum extra payload size in bytes.
pub const MAX_TX_EXTRA_PAYLOAD: usize = 10_000;

/// Maximum coinbase script size in bytes.
pub const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

/// Size of the quorum signing info that ends an asset unlock payload, made
/// of the requested height, quorum hash and quorum signature.
const ASSET_UNLOCK_QUORUM_INFO_SIZE: usize = size_of::<u32>() + size_of::<QuorumHash>() + size_of::<BlsSigBytes>();

/// Size of an asset unlock payload.
const ASSET_UNLOCK_PAYLOAD_SIZE: usize =
  size_of::<u8>() + size_of::<u64>() + size_of::<u32>() + ASSET_UNLOCK_QUORUM_INFO_SIZE;

make_hash! {
  /// SHA256d hash of a serialized transaction.
  TxHash, 32
}

hash_impl!(TxHash);

codec_type! {
/// A reference to a previous transaction output.
#[derive(Debug, Clone, Copy, CopyGetters, PartialEq, Eq, Hash, PartialOrd, Ord, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OutPoint {
  /// Transaction hash of the referenced output.
  #[cfg_attr(feature = "serde", serde(rename = "hash"))]
  #[getset(get_copy = "pub")]
  txid: TxHash,
  /// Index of the referenced output within the transaction.
  #[getset(get_copy = "pub")]
  index: u32,
}
}

impl OutPoint {
  /// Returns `true` for the null outpoint (all-zero hash, index `u32::MAX`).
  pub fn is_null(&self) -> bool {
    self.txid.is_null() && self.index == u32::MAX
  }
}

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.txid, self.index)
  }
}

codec_type! {
/// A transaction input.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxIn {
  /// The outpoint being spent.
  #[getset(get_copy = "pub")]
  prevout: OutPoint,
  /// Unlocking script.
  #[getset(get = "pub")]
  script_sig: ScriptSigBuf,
  /// Sequence number.
  #[getset(get_copy = "pub")]
  sequence: u32,
}
}

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}

impl_new! {
/// A transaction output.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxOut {
  /// Output value in duffs.
  #[cfg_attr(feature = "serde", serde(with = "bitcoin_units::amount::serde::as_sat"))]
  #[getset(get_copy = "pub")]
  value: SignedAmount,
  /// Locking script.
  #[cfg_attr(feature = "serde", serde(rename = "scriptPubKey"))]
  #[getset(get = "pub")]
  script_pubkey: ScriptPubKeyBuf,
}
}

impl_type!(TxOut);

impl BaseCodec for TxOut {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = i64::decode(data)?;
    let value = SignedAmount::from_sat(raw).map_err(|_| DecodeError::InvalidValue {
      expected: vec![SignedAmount::MAX_MONEY.to_sat().cast_unsigned()],
      actual: raw.cast_unsigned(),
    })?;
    Ok(Self {
      value,
      script_pubkey: ScriptPubKeyBuf::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.value.to_sat().encode(buf);
    self.script_pubkey.encode(buf);
  }
}

hash_impl!(TxOut);

impl fmt::Display for TxOut {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxOut {{ value: {} }}", self.value.to_sat())
  }
}

/// Transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum TxInvalid {
  /// `bad-txns-vin-empty`
  #[error("bad-txns-vin-empty")]
  EmptyInputs,
  /// `bad-txns-vout-empty`
  #[error("bad-txns-vout-empty")]
  EmptyOutputs,
  /// `bad-txns-oversize`
  #[error("bad-txns-oversize: {size} bytes")]
  Oversize { size: usize },
  /// `bad-txns-payload-oversize`
  #[error("bad-txns-payload-oversize: {size} bytes")]
  PayloadOversize { size: usize },
  /// `bad-txns-vout-negative`
  #[error("bad-txns-vout-negative: output {index} value {value}")]
  OutputNegative { index: usize, value: i64 },
  /// `bad-txns-txouttotal-toolarge`
  #[error("bad-txns-txouttotal-toolarge: {total}")]
  OutputTotalTooLarge { total: i64 },
  /// `bad-txns-inputs-duplicate`
  #[error("bad-txns-inputs-duplicate: {outpoint}")]
  DuplicateInputs { outpoint: OutPoint },
  /// `bad-cb-length`
  #[error("bad-cb-length: {len}")]
  BadCoinbaseScriptLength { len: usize },
  /// `bad-txns-prevout-null`
  #[error("bad-txns-prevout-null: input {index}")]
  NullPrevout { index: usize },
  /// `bad-txns-payload-not-allowed`
  #[error("bad-txns-payload-not-allowed")]
  PayloadNotAllowed,
  /// `bad-txns-payload-decode`
  #[error("bad-txns-payload-decode: {0}")]
  PayloadDecode(PayloadError),
  /// `bad-txns-payload-check`
  #[error("bad-txns-payload-check: {0}")]
  PayloadCheck(PayloadInvalid),
}

impl_new! {
/// A Dash transaction.
///
/// The wire format packs `version` (i16) and `tx_type` (u16) into a single
/// `i32`: `raw = (tx_type << 16) | (version & 0xffff)`.
///
/// Special transactions (type != Spend, version >= 3) carry an `extra_payload`
/// decoded separately by payload-specific decoders.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Transaction {
  /// Transaction version (lower 16 bits of the wire i32).
  #[getset(get_copy = "pub")]
  version: i16,
  /// Transaction type (upper 16 bits of the wire i32).
  #[getset(get_copy = "pub")]
  tx_type: TxType,
  /// Transaction inputs.
  #[getset(get = "pub")]
  inputs: Vec<TxIn>,
  /// Transaction outputs.
  #[getset(get = "pub")]
  outputs: Vec<TxOut>,
  /// Lock time.
  #[getset(get_copy = "pub")]
  lock_time: u32,
  /// Extra payload for special transactions.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  extra_payload: Vec<u8>,
}
}

impl_type!(Transaction);

impl BaseCodec for Transaction {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = i32::decode(data)?;
    let version = raw as i16;
    let tx_type = TxType::from_base(((raw >> 16) & 0xffff) as u16);

    Ok(Self {
      version,
      tx_type,
      inputs: Vec::decode(data)?,
      outputs: Vec::decode(data)?,
      lock_time: u32::decode(data)?,
      extra_payload: if version >= 3 && tx_type != TxType::Spend {
        let len = CompactSize::decode_len(data, crate::codec::MAX_SPTX_PAYLOAD_SIZE)?;
        codec::read_bytes(data, len)?.to_vec()
      } else {
        Vec::new()
      },
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.raw_version().encode(buf);
    self.inputs.encode(buf);
    self.outputs.encode(buf);
    self.lock_time.encode(buf);
    if self.has_extra_payload() {
      self.extra_payload.encode(buf);
    }
  }
}

impl Checkable for Transaction {
  type Error = TxInvalid;

  fn check(&self) -> Option<Self::Error> {
    let allows_empty_vin = matches!(
      self.tx_type,
      TxType::QuorumCommitment | TxType::MnhfSignal | TxType::AssetUnlock
    );
    let allows_empty_vout = matches!(self.tx_type, TxType::QuorumCommitment | TxType::MnhfSignal);

    if !allows_empty_vin && self.inputs.is_empty() {
      return Some(TxInvalid::EmptyInputs);
    }
    if !allows_empty_vout && self.outputs.is_empty() {
      return Some(TxInvalid::EmptyOutputs);
    }

    let size = codec::encoded_size(self);
    if size > MAX_LEGACY_BLOCK_SIZE {
      return Some(TxInvalid::Oversize { size });
    }

    if !self.has_extra_payload() && !self.extra_payload.is_empty() {
      return Some(TxInvalid::PayloadNotAllowed);
    }
    if self.extra_payload.len() > MAX_TX_EXTRA_PAYLOAD {
      return Some(TxInvalid::PayloadOversize {
        size: self.extra_payload.len(),
      });
    }

    let mut total = SignedAmount::ZERO;
    for (i, output) in self.outputs.iter().enumerate() {
      let value = output.value;
      if value.is_negative() {
        return Some(TxInvalid::OutputNegative {
          index: i,
          value: value.to_sat(),
        });
      }
      total = match total.checked_add(value) {
        Some(sum) => sum,
        None => {
          return Some(TxInvalid::OutputTotalTooLarge {
            total: total.to_sat() + value.to_sat(),
          })
        }
      };
    }

    // Duplicate inputs (CVE-2018-17144).
    if self.inputs.len() > 1 {
      let mut seen = BTreeSet::new();
      for input in &self.inputs {
        if !seen.insert(&input.prevout) {
          return Some(TxInvalid::DuplicateInputs {
            outpoint: input.prevout,
          });
        }
      }
    }

    if self.is_coinbase() {
      let min_cb_size = if self.tx_type == TxType::CoinbaseCommitment {
        1
      } else {
        2
      };
      let cb_len = self.inputs[0].script_sig.len();
      if cb_len < min_cb_size || cb_len > MAX_COINBASE_SCRIPT_SIZE {
        return Some(TxInvalid::BadCoinbaseScriptLength { len: cb_len });
      }
    } else {
      for (i, input) in self.inputs.iter().enumerate() {
        if input.prevout.is_null() {
          return Some(TxInvalid::NullPrevout { index: i });
        }
      }
    }

    if let Some(result) = self.decode_payload() {
      match result {
        Ok(ref payload) if payload.is_unknown() => {
          return Some(TxInvalid::PayloadCheck(PayloadInvalid::UnknownType(self.tx_type)));
        }
        Ok(payload) => {
          if let Some(e) = payload.check() {
            return Some(TxInvalid::PayloadCheck(e));
          }
        }
        Err(e) => return Some(TxInvalid::PayloadDecode(e)),
      }
    }

    None
  }
}

impl Hashable for Transaction {
  type Hash = TxHash;

  /// Returns the txid. An asset unlock with a stable txid is hashed with its
  /// quorum signing info zeroed; see [`Transaction::has_stable_txid`].
  fn hash(&self) -> TxHash {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    if self.has_stable_txid() {
      let start = buf.len() - ASSET_UNLOCK_QUORUM_INFO_SIZE;
      buf[start..].fill(0);
    }
    TxHash::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl Transaction {
  /// Returns the packed i32 version field as on the wire.
  pub fn raw_version(&self) -> i32 {
    let v = (self.version as u16) as i32;
    let t = (self.tx_type.to_base() as i32) << 16;
    v | t
  }

  /// Returns the hash of the whole serialization. It differs from the txid
  /// only for an asset unlock with a stable txid.
  pub fn instance_hash(&self) -> TxHash {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    TxHash::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }

  /// Returns `true` for an asset unlock whose payload has the size of a valid
  /// one and a version of at least 2.
  ///
  /// Its txid leaves out the quorum signing info, so re-signing it keeps the
  /// txid. Only the payload size and first byte are read, before any
  /// validation.
  pub fn has_stable_txid(&self) -> bool {
    self.has_extra_payload()
      && self.tx_type == TxType::AssetUnlock
      && self.extra_payload.len() == ASSET_UNLOCK_PAYLOAD_SIZE
      && self.extra_payload[0] >= 2
  }

  /// Returns true when this transaction carries an extra payload.
  fn has_extra_payload(&self) -> bool {
    self.version >= 3 && self.tx_type != TxType::Spend
  }

  /// Decodes the special transaction payload, if present.
  ///
  /// Returns `None` for spend/coinbase transactions that carry no extra
  /// payload.
  ///
  /// # Errors
  ///
  /// Returns `PayloadError` if the payload bytes cannot be decoded for the
  /// declared transaction type.
  pub fn decode_payload(&self) -> Option<Result<crate::sptx::SpecialPayload, crate::sptx::PayloadError>> {
    if !self.has_extra_payload() {
      return None;
    }
    let mut cursor = &self.extra_payload[..];
    let result = crate::sptx::SpecialPayload::decode(self.tx_type, &mut cursor);
    Some(result.and_then(|payload| {
      if !cursor.is_empty() {
        return Err(crate::sptx::PayloadError::new(
          self.tx_type,
          format!("trailing bytes: {} remaining", cursor.len()),
        ));
      }
      Ok(payload)
    }))
  }

  /// Returns `true` when the only input spends the null outpoint.
  pub(crate) fn is_coinbase(&self) -> bool {
    self.inputs.len() == 1 && self.inputs[0].prevout.is_null()
  }
}

impl fmt::Display for Transaction {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "Transaction {{ v{}, {}, {} in, {} out }}",
      self.version,
      self.tx_type,
      self.inputs.len(),
      self.outputs.len(),
    )
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
pub(crate) mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_tx, Corpus};
  use rstest::rstest;
  use serde::Deserialize;

  #[rstest]
  #[case("spend")]
  #[case("coinbase")]
  #[case("data")]
  fn corpus_tx(#[case] section: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), section);
    let items = corpus.entries::<Transaction>(section, check_tx);
    assert_serde_rt(section, &items);
  }

  #[derive(Deserialize)]
  struct CheckVector {
    #[serde(rename = "type")]
    tx_type: u16,
    inputs: Vec<u8>,
    script_sig: usize,
    values: Vec<i64>,
    pad: usize,
    payload: usize,
    size: usize,
    reason: String,
  }

  impl CheckVector {
    fn build(&self) -> Transaction {
      let inputs = self.inputs.iter().enumerate().map(|(i, &seed)| TxIn {
        prevout: OutPoint {
          txid: TxHash::from_lendian([seed; 32]),
          index: if seed == 0 { u32::MAX } else { 0 },
        },
        script_sig: ScriptSigBuf::from_bytes(vec![0; if i == 0 { self.script_sig } else { 0 }]),
        sequence: u32::MAX,
      });
      let outputs = self.values.iter().enumerate().map(|(i, &value)| TxOut {
        value: SignedAmount::from_sat(value).unwrap(),
        script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0; if i == 0 { self.pad } else { 0 }]),
      });
      Transaction {
        version: 3,
        tx_type: TxType::from_base(self.tx_type),
        inputs: inputs.collect(),
        outputs: outputs.collect(),
        lock_time: 0,
        extra_payload: vec![0; self.payload],
      }
    }
  }

  /// Payload checks run after every check the vectors cover, so payload
  /// errors count as a pass.
  pub(crate) fn reason(result: Option<TxInvalid>) -> String {
    match result {
      None | Some(TxInvalid::PayloadDecode(_) | TxInvalid::PayloadCheck(_)) => String::new(),
      Some(error) => error.to_string().split(':').next().unwrap_or_default().into(),
    }
  }

  #[rstest]
  fn check_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "tx_check");
    for (i, v) in corpus.vectors::<CheckVector>("check").into_iter().enumerate() {
      let tx = v.build();
      let mut buf = Vec::new();
      tx.encode(&mut buf);
      assert_eq!(buf.len(), v.size, "vector {i}");
      assert_eq!(reason(tx.check()), v.reason, "vector {i}");
    }
  }

  #[rstest]
  #[case::negative(&[-1], 0)]
  #[case::after_valid(&[1, -1], 1)]
  #[case::total_in_range(&[SignedAmount::MAX_MONEY.to_sat(), -1], 1)]
  fn check_negative_output(#[case] values: &[i64], #[case] index: usize) {
    let input = TxIn::new(
      OutPoint::new(TxHash::from_lendian([1; 32]), 0),
      ScriptSigBuf::new(),
      u32::MAX,
    );
    let outputs = values
      .iter()
      .map(|&value| TxOut::new(SignedAmount::from_sat(value).unwrap(), ScriptPubKeyBuf::new()))
      .collect();
    let tx = Transaction::new(3, TxType::Spend, vec![input], outputs, 0, Vec::new());
    let value = values[index];
    assert_eq!(tx.check(), Some(TxInvalid::OutputNegative { index, value }));
  }

  #[rstest]
  #[case::lowest(-SignedAmount::MAX_MONEY.to_sat(), true)]
  #[case::highest(SignedAmount::MAX_MONEY.to_sat(), true)]
  #[case::below_range(-SignedAmount::MAX_MONEY.to_sat() - 1, false)]
  #[case::above_range(SignedAmount::MAX_MONEY.to_sat() + 1, false)]
  #[case::i64_min(i64::MIN, false)]
  #[case::i64_max(i64::MAX, false)]
  fn decode_output_value(#[case] value: i64, #[case] decodes: bool) {
    let mut raw = value.to_le_bytes().to_vec();
    raw.push(0);
    assert_eq!(TxOut::decode(&mut &raw[..]).is_ok(), decodes);
  }

  /// A mainnet asset unlock with a version 1 payload.
  const MAINNET_UNLOCK: &str = "65fc488b35abd172726238a16cc71ef11eecb034ce05991e9a3e5ba4fd85094f";

  /// A regtest asset unlock with a version 2 payload.
  const REGTEST_UNLOCK: &str = "0f9db35643e5ebca413fe5be12144185adb7236f051dbcb872162c14cea2523a";

  /// The asset unlock `txid` of the corpus.
  fn unlock(txid: &str) -> Transaction {
    let mut tx = None;
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    corpus.entries::<crate::AssetUnlock>("assetunlock", |raw, _, label| {
      if label == txid {
        tx = Some(Transaction::decode(&mut &raw[..]).unwrap());
      }
    });
    tx.unwrap()
  }

  #[rstest]
  #[case::v1(|_: &mut Transaction| {}, false)]
  #[case::v2(|tx: &mut Transaction| tx.extra_payload[0] = 2, true)]
  #[case::v3(|tx: &mut Transaction| tx.extra_payload[0] = 3, true)]
  #[case::v2_short(
    |tx: &mut Transaction| {
      tx.extra_payload[0] = 2;
      tx.extra_payload.pop();
    },
    false
  )]
  #[case::v2_long(
    |tx: &mut Transaction| {
      tx.extra_payload[0] = 2;
      tx.extra_payload.push(0);
    },
    false
  )]
  #[case::v2_asset_lock(
    |tx: &mut Transaction| {
      tx.extra_payload[0] = 2;
      tx.tx_type = TxType::AssetLock;
    },
    false
  )]
  #[case::v2_tx_version_2(
    |tx: &mut Transaction| {
      tx.extra_payload[0] = 2;
      tx.version = 2;
    },
    false
  )]
  fn stable_txid(#[case] edit: fn(&mut Transaction), #[case] stable: bool) {
    let mut tx = unlock(MAINNET_UNLOCK);
    edit(&mut tx);
    assert_eq!(tx.has_stable_txid(), stable);
    assert_eq!(tx.hash() != tx.instance_hash(), stable);
  }

  /// A stable txid leaves out the requested height, quorum hash and quorum
  /// signature.
  #[rstest]
  #[case::v1_signature(1, 144, false)]
  #[case::v2_index(2, 1, false)]
  #[case::v2_fee(2, 12, false)]
  #[case::v2_requested_height(2, 13, true)]
  #[case::v2_signature(2, 144, true)]
  fn stable_txid_leaves_out_quorum_info(#[case] version: u8, #[case] at: usize, #[case] kept: bool) {
    let mut tx = unlock(MAINNET_UNLOCK);
    tx.extra_payload[0] = version;
    let mut other = tx.clone();
    other.extra_payload[at] ^= 1;
    assert_eq!(other.hash() == tx.hash(), kept);
    assert_ne!(other.instance_hash(), tx.instance_hash());
  }

  /// The instance hash that the reference reports for the regtest unlock.
  #[rstest]
  fn instance_hash_matches_reference() {
    let expected = TxHash::from_hex("4661437eee9c8b84d6c966f396c93993f56a58140f916d3249a805859a07efb6").unwrap();
    assert_eq!(unlock(REGTEST_UNLOCK).instance_hash(), expected);
  }
}
