//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash transaction with version/type packing and optional extra payload for
//! special transactions.

use crate::prelude::*;
use crate::sptx::{PayloadError, PayloadInvalid, TxType};
use crate::{codec_type, hash_impl};

use bitcoin_hashes::sha256d;
use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin_units::Amount;
use dash_num::make_hash;
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable, CompactSize, Hashable, Numeric};

use core::fmt;

/// Maximum extra payload size in bytes.
pub const MAX_TX_EXTRA_PAYLOAD: usize = 10_000;

/// Maximum coinbase script size in bytes.
pub const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

make_hash! {
  /// SHA256d hash of a serialized transaction.
  TxHash, 32
}

hash_impl!(TxHash);

/// A reference to a previous transaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OutPoint {
  /// Transaction hash of the referenced output.
  pub hash: TxHash,
  /// Index of the referenced output within the transaction.
  pub index: u32,
}

codec_type!(OutPoint { hash, index });

impl OutPoint {
  /// Returns `true` for the null outpoint (all-zero hash, index `u32::MAX`).
  pub fn is_null(&self) -> bool {
    self.hash.is_null() && self.index == u32::MAX
  }
}

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.hash, self.index)
  }
}

/// A transaction input.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxIn {
  /// The outpoint being spent.
  pub prevout: OutPoint,
  /// Unlocking script.
  pub script_sig: ScriptSigBuf,
  /// Sequence number.
  pub sequence: u32,
}

codec_type!(TxIn {
  prevout,
  script_sig,
  sequence
});

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}

/// A transaction output.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxOut {
  /// Output value in duffs.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  pub value: Amount,
  /// Locking script.
  #[cfg_attr(feature = "serde", serde(rename = "scriptPubKey"))]
  pub script_pubkey: ScriptPubKeyBuf,
}

impl_type!(TxOut);

impl BaseCodec for TxOut {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = u64::decode(data)?;
    let value = Amount::from_sat(raw).map_err(|_| DecodeError::InvalidValue {
      expected: vec![Amount::MAX_MONEY.to_sat()],
      actual: raw,
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
  /// `bad-txns-vout-toolarge`
  #[error("bad-txns-vout-toolarge: output {index} value {value}")]
  OutputTooLarge { index: usize, value: u64 },
  /// `bad-txns-txouttotal-toolarge`
  #[error("bad-txns-txouttotal-toolarge: {total}")]
  OutputTotalTooLarge { total: u64 },
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

/// An encode target that counts the bytes written instead of storing them.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Unencodable)]
struct ByteCount(usize);

impl EncodeBuf for ByteCount {
  fn push(&mut self, _byte: u8) {
    self.0 += 1;
  }

  fn extend_from_slice(&mut self, data: &[u8]) {
    self.0 += data.len();
  }
}

/// A Dash transaction.
///
/// The wire format packs `version` (i16) and `tx_type` (u16) into a single
/// `i32`: `raw = (tx_type << 16) | (version & 0xffff)`.
///
/// Special transactions (type != Spend, version >= 3) carry an `extra_payload`
/// decoded separately by payload-specific decoders.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Transaction {
  /// Transaction version (lower 16 bits of the wire i32).
  pub version: i16,
  /// Transaction type (upper 16 bits of the wire i32).
  pub tx_type: TxType,
  /// Transaction inputs.
  pub inputs: Vec<TxIn>,
  /// Transaction outputs.
  pub outputs: Vec<TxOut>,
  /// Lock time.
  pub lock_time: u32,
  /// Extra payload for special transactions.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub extra_payload: Vec<u8>,
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
        let len = CompactSize::decode(data)?.into_len(crate::codec::MAX_SPTX_PAYLOAD_SIZE)?;
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

    let mut size = ByteCount::default();
    self.encode(&mut size);
    if size.0 > crate::MAX_LEGACY_BLOCK_SIZE {
      return Some(TxInvalid::Oversize { size: size.0 });
    }

    if !self.has_extra_payload() && !self.extra_payload.is_empty() {
      return Some(TxInvalid::PayloadNotAllowed);
    }
    if self.extra_payload.len() > MAX_TX_EXTRA_PAYLOAD {
      return Some(TxInvalid::PayloadOversize {
        size: self.extra_payload.len(),
      });
    }

    let max_money = bitcoin_units::Amount::MAX_MONEY.to_sat();
    let mut total: u64 = 0;
    for (i, output) in self.outputs.iter().enumerate() {
      let sat = output.value.to_sat();
      if sat > max_money {
        return Some(TxInvalid::OutputTooLarge { index: i, value: sat });
      }
      total = total.saturating_add(sat);
      if total > max_money {
        return Some(TxInvalid::OutputTotalTooLarge { total });
      }
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

  fn hash(&self) -> TxHash {
    let mut buf = Vec::new();
    self.encode(&mut buf);
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
        return Err(crate::sptx::PayloadError {
          tx_type: self.tx_type,
          message: format!("trailing bytes: {} remaining", cursor.len()),
        });
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
mod tests {
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
    values: Vec<u64>,
    pad: usize,
    payload: usize,
    size: usize,
    reason: String,
  }

  impl CheckVector {
    fn build(&self) -> Transaction {
      let inputs = self.inputs.iter().enumerate().map(|(i, &seed)| TxIn {
        prevout: OutPoint {
          hash: TxHash::from_lendian([seed; 32]),
          index: if seed == 0 { u32::MAX } else { 0 },
        },
        script_sig: ScriptSigBuf::from_bytes(vec![0; if i == 0 { self.script_sig } else { 0 }]),
        sequence: u32::MAX,
      });
      let outputs = self.values.iter().enumerate().map(|(i, &value)| TxOut {
        value: Amount::from_sat(value).unwrap(),
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
  fn reason(result: Option<TxInvalid>) -> &'static str {
    match result {
      None | Some(TxInvalid::PayloadDecode(_) | TxInvalid::PayloadCheck(_)) => "",
      Some(TxInvalid::EmptyInputs) => "bad-txns-vin-empty",
      Some(TxInvalid::EmptyOutputs) => "bad-txns-vout-empty",
      Some(TxInvalid::Oversize { .. }) => "bad-txns-oversize",
      Some(TxInvalid::PayloadOversize { .. }) => "bad-txns-payload-oversize",
      Some(TxInvalid::OutputTooLarge { .. }) => "bad-txns-vout-toolarge",
      Some(TxInvalid::OutputTotalTooLarge { .. }) => "bad-txns-txouttotal-toolarge",
      Some(TxInvalid::DuplicateInputs { .. }) => "bad-txns-inputs-duplicate",
      Some(TxInvalid::BadCoinbaseScriptLength { .. }) => "bad-cb-length",
      Some(TxInvalid::NullPrevout { .. }) => "bad-txns-prevout-null",
      Some(TxInvalid::PayloadNotAllowed) => "bad-txns-payload-not-allowed",
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
}
