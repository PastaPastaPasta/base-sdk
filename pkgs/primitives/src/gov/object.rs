//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance objects and proposal payloads.

use crate::prelude::*;
use crate::transaction::OutPoint;
use crate::{codec_base, hash_impl, TxHash};

use bitcoin_hashes::sha256d;
use bitcoin_units::Amount;
use dash_num::Hash256;
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_new, impl_num, Checkable, Hashable, Numeric};
use getset::{CopyGetters, Getters};
use hex_conservative::DisplayHex;

/// Maximum allowed name length for governance proposals.
const MAX_PROPOSAL_NAME_LEN: usize = 40;

/// Minimum URL length for governance proposals.
const MIN_URL_LEN: usize = 4;

/// Allowed characters in governance proposal names.
const PROPOSAL_NAME_CHARS: &[u8] = b"-_abcdefghijklmnopqrstuvwxyz0123456789";

enum_map! {
  /// Governance object type codes.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum GovObjectType, i32, Unknown {
    /// Budget proposal.
    Proposal = 1 => "proposal",
    /// Superblock trigger.
    Trigger = 2 => "trigger",
  }
}

impl_num!(GovObjectType, i32);

hash_impl!(GovObjectType);

impl_new! {
/// A governance proposal payload (type 1 JSON).
///
/// ```json
/// {
///   "type": 1,
///   "name": "proposal-name",
///   "url": "https://example.com/proposal",
///   "payment_address": "XaddressHere",
///   "payment_amount": "10.5",
///   "start_epoch": 1700000000,
///   "end_epoch": 1703000000
/// }
/// ```
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Proposal {
  /// Short name (max 40 chars, lowercase alphanum + `-_`).
  #[getset(get = "pub")]
  name: String,
  /// Proposal URL.
  #[getset(get = "pub")]
  url: String,
  /// Dash address receiving payment.
  #[getset(get = "pub")]
  payment_address: String,
  /// Payment amount.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  #[getset(get_copy = "pub")]
  payment_amount: Amount,
  /// Unix timestamp when payments begin.
  #[getset(get_copy = "pub")]
  start_epoch: i64,
  /// Unix timestamp when payments end.
  #[getset(get_copy = "pub")]
  end_epoch: i64,
}
}

impl_new! {
/// A superblock trigger payload (type 2 JSON).
///
/// ```json
/// {
///   "type": 2,
///   "event_block_height": 123456,
///   "payment_addresses": "addr1|addr2",
///   "payment_amounts": "10.5|20.0",
///   "proposal_hashes": "hash1|hash2"
/// }
/// ```
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Trigger {
  /// Block height at which payments occur.
  #[getset(get_copy = "pub")]
  event_block_height: i32,
  /// Pipe-delimited payment addresses.
  #[getset(get = "pub")]
  payment_addresses: String,
  /// Pipe-delimited payment amounts.
  #[getset(get = "pub")]
  payment_amounts: String,
  /// Pipe-delimited proposal hashes.
  #[getset(get = "pub")]
  proposal_hashes: String,
}
}

/// Decoded governance object data payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum GovData {
  /// Budget proposal.
  Proposal(Proposal),
  /// Superblock trigger.
  Trigger(Trigger),
  /// Opaque data for unknown types.
  Unknown(Vec<u8>),
}

impl_new! {
/// Governance object.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovObject {
  /// Parent object hash (zero for root).
  #[getset(get_copy = "pub")]
  hash_parent: TxHash,
  /// Object revision.
  #[getset(get_copy = "pub")]
  revision: i32,
  /// Creation timestamp.
  #[getset(get_copy = "pub")]
  time: i64,
  /// Collateral transaction hash.
  #[getset(get_copy = "pub")]
  collateral_hash: TxHash,
  /// Raw data bytes (JSON when decoded as string).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  data: Vec<u8>,
  /// Object type code.
  #[getset(get_copy = "pub")]
  object_type: GovObjectType,
  /// Signing masternode outpoint.
  #[getset(get_copy = "pub")]
  masternode_outpoint: OutPoint,
  /// BLS or ECDSA signature.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  sig: Vec<u8>,
}
}

codec_base!(GovObject, dash_types::MAX_SER_SIZE, {
  hash_parent,
  revision,
  time,
  collateral_hash,
  data,
  object_type,
  masternode_outpoint,
  sig: Self::MAX_SIGNATURE_SIZE,
});

impl Hashable for GovObject {
  type Hash = Hash256;

  /// Computes the canonical governance object hash.
  ///
  /// The hash input differs from the wire format: `collateral_hash` and
  /// `object_type` are excluded, and `data` is hex-encoded as ASCII bytes
  /// before hashing.
  fn hash(&self) -> Hash256 {
    let data_hex = self.data.to_lower_hex_string();

    let mut buf = Vec::new();
    self.hash_parent.encode(&mut buf);
    self.revision.encode(&mut buf);
    self.time.encode(&mut buf);
    // data hex is serialized as a string (CompactSize + bytes)
    data_hex.encode(&mut buf);
    // outpoint + dummy padding for legacy hash compat
    self.masternode_outpoint.txid().encode(&mut buf);
    self.masternode_outpoint.index().encode(&mut buf);
    0u8.encode(&mut buf);
    0xFFFF_FFFFu32.encode(&mut buf);
    self.sig.encode(&mut buf);

    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl GovObject {
  /// The most signature bytes a governance object carries.
  pub const MAX_SIGNATURE_SIZE: usize = 96;

  /// Returns the data as a UTF-8 string, if valid.
  pub fn data_as_string(&self) -> Option<&str> {
    core::str::from_utf8(&self.data).ok()
  }

  /// Returns the data as a hex string.
  pub fn data_as_hex(&self) -> String {
    self.data.to_lower_hex_string()
  }
}

/// Governance proposal validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum ProposalInvalid {
  /// Name is empty.
  #[error("invalid name: empty")]
  NameEmpty,
  /// Name exceeds maximum length.
  #[error("invalid name: {len} chars exceeds {}", MAX_PROPOSAL_NAME_LEN)]
  NameTooLong { len: usize },
  /// Name contains invalid characters.
  #[error("invalid name: disallowed characters")]
  NameInvalidChars,
  /// `end_epoch` is not after `start_epoch`.
  #[error("invalid start:end range")]
  BadEpochRange,
  /// Payment amount is not positive.
  #[error("invalid payment amount")]
  BadPaymentAmount,
  /// URL is too short.
  #[error("url too short: {len} chars")]
  UrlTooShort { len: usize },
  /// URL contains whitespace.
  #[error("url has whitespace")]
  UrlWhitespace,
}

impl Checkable for Proposal {
  type Error = ProposalInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.name.is_empty() {
      return Some(ProposalInvalid::NameEmpty);
    }
    if self.name.len() > MAX_PROPOSAL_NAME_LEN {
      return Some(ProposalInvalid::NameTooLong { len: self.name.len() });
    }
    if !self
      .name
      .bytes()
      .all(|b| PROPOSAL_NAME_CHARS.contains(&b.to_ascii_lowercase()))
    {
      return Some(ProposalInvalid::NameInvalidChars);
    }

    if self.end_epoch <= self.start_epoch {
      return Some(ProposalInvalid::BadEpochRange);
    }

    if self.payment_amount == Amount::ZERO {
      return Some(ProposalInvalid::BadPaymentAmount);
    }

    if self.url.len() < MIN_URL_LEN {
      return Some(ProposalInvalid::UrlTooShort { len: self.url.len() });
    }
    if self.url.bytes().any(|b| b.is_ascii_whitespace()) {
      return Some(ProposalInvalid::UrlWhitespace);
    }

    None
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, from_json_slice, Corpus, Value};
  use dash_types::codec::DecodeError;
  use rstest::rstest;
  use serde::{Deserialize, Serialize};

  #[rstest]
  fn corpus_govobj_wire() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobj");
    corpus.entries::<Value>("govobj", |raw, _, label| {
      let decoded = GovObject::decode(&mut &raw[..]).unwrap();
      let mut encoded = Vec::new();
      decoded.encode(&mut encoded);
      assert_eq!(encoded, raw, "{label}: encode");
    });
  }

  /// Corpus representation of a governance object.
  ///
  /// Mirrors [`GovObject`] but stores the inner `data` payload as
  /// structured JSON instead of a hex blob.
  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  struct GovCorpusDetails {
    hash_parent: TxHash,
    revision: i32,
    collateral_hash: TxHash,
    object_type: GovObjectType,
    time: i64,
    masternode_outpoint: OutPoint,
    #[serde(with = "dash_types::serialize::hex")]
    sig: Vec<u8>,
    data: Value,
  }

  impl GovCorpusDetails {
    fn assert_matches(&self, obj: &GovObject, label: &str) {
      assert_eq!(self.hash_parent, obj.hash_parent, "{label}: hash_parent");
      assert_eq!(self.revision, obj.revision, "{label}: revision");
      assert_eq!(self.time, obj.time, "{label}: time");
      assert_eq!(self.collateral_hash, obj.collateral_hash, "{label}: collateral_hash");
      assert_eq!(self.object_type, obj.object_type, "{label}: object_type");
      assert_eq!(
        self.masternode_outpoint, obj.masternode_outpoint,
        "{label}: masternode_outpoint"
      );
      assert_eq!(self.sig, obj.sig, "{label}: sig");

      let wire_data: Value = from_json_slice(&obj.data);
      assert_eq!(self.data, wire_data, "{label}: data");
    }
  }

  #[rstest]
  #[case("proposals")]
  #[case("triggers")]
  fn corpus_govobj(#[case] section: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), section);
    let items = corpus.entries::<GovCorpusDetails>(section, |raw, details, label| {
      let obj = GovObject::decode(&mut &raw[..]).unwrap();
      details.assert_matches(&obj, label);

      if obj.object_type == GovObjectType::Proposal {
        let proposal: Proposal = from_json_slice(&obj.data);
        if let Some(e) = proposal.check() {
          panic!("{label}: proposal check: {e}");
        }
      }

      let mut encoded = Vec::new();
      obj.encode(&mut encoded);
      assert_eq!(encoded, raw, "{label}: encode");

      let expected_hash = Hash256::from_hex(label).unwrap();
      assert_eq!(obj.hash(), expected_hash, "{label}: hash");
    });
    assert_serde_rt(section, &items);
  }

  fn govobj_with_sig(len: usize) -> GovObject {
    GovObject::new(
      TxHash::default(),
      1,
      0,
      TxHash::default(),
      b"{}".to_vec(),
      GovObjectType::Proposal,
      OutPoint::new(TxHash::default(), 0),
      vec![0xAB; len],
    )
  }

  #[rstest]
  #[case::empty(0)]
  #[case::at_the_bound(96)]
  fn decodes_a_sig_up_to_the_bound(#[case] len: usize) {
    let obj = govobj_with_sig(len);
    let mut wire = Vec::new();
    obj.encode(&mut wire);
    assert_eq!(GovObject::decode(&mut &wire[..]), Ok(obj));
  }

  /// The count is refused before any signature byte is read.
  #[rstest]
  #[case::with_the_bytes(true)]
  #[case::without_the_bytes(false)]
  fn refuses_a_sig_one_over_the_bound(#[case] with_bytes: bool) {
    let over = 97;
    let mut wire = Vec::new();
    govobj_with_sig(over).encode(&mut wire);
    if !with_bytes {
      wire.truncate(wire.len() - over);
    }
    assert_eq!(
      GovObject::decode(&mut &wire[..]),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: GovObject::MAX_SIGNATURE_SIZE,
        value: over as u64
      })
    );
  }
}
