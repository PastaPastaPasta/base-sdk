//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance votes.

use crate::prelude::*;
use crate::transaction::OutPoint;
use crate::{hash_impl, TxHash};

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_num, impl_type, ArrayBuf, CompactSize, Hashable, Numeric};

/// Length of a compact ECDSA vote signature.
const VOTE_COMPACT_SIG_SIZE: usize = 65;

/// Length of a BLS vote signature.
const VOTE_BLS_SIG_SIZE: usize = 96;

enum_map! {
  /// Governance vote outcome.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum VoteOutcome, u32, Unknown {
    /// No vote cast.
    None = 0 => "none",
    /// Vote in favour.
    Yes = 1 => "yes",
    /// Vote against.
    No = 2 => "no",
    /// Abstention.
    Abstain = 3 => "abstain",
  }
}

impl_num!(VoteOutcome, u32);

hash_impl!(VoteOutcome);

enum_map! {
  /// Governance vote signal type.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum VoteSignal, u32, Unknown {
    /// No signal.
    None = 0 => "none",
    /// Fund this object.
    Funding = 1 => "funding",
    /// Object checks out.
    Valid = 2 => "valid",
    /// Object should be deleted.
    Delete = 3 => "delete",
    /// Officially endorsed.
    Endorsed = 4 => "endorsed",
  }
}

impl_num!(VoteSignal, u32);

hash_impl!(VoteSignal);

/// A governance vote.
///
/// ```text
/// masternode_outpoint(36) || parent_hash(32)
/// || outcome(u32) || signal(u32) || time(i64)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovVote {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp.
  pub time: i64,
  /// Signature bytes. Decoding accepts only 65 or 96 bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

impl BaseCodec for GovVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let masternode_outpoint = OutPoint::decode(data)?;
    let parent_hash = TxHash::decode(data)?;
    let outcome = VoteOutcome::decode(data)?;
    let signal = VoteSignal::decode(data)?;
    let time = i64::decode(data)?;
    let len = CompactSize::decode(data)?.into_len(VOTE_BLS_SIG_SIZE)?;
    let sig = codec::read_bytes(data, len)?.to_vec();
    if len != VOTE_COMPACT_SIG_SIZE && len != VOTE_BLS_SIG_SIZE {
      return Err(DecodeError::BadLen {
        expected: vec![VOTE_COMPACT_SIG_SIZE, VOTE_BLS_SIG_SIZE],
        actual: len,
      });
    }
    Ok(Self {
      masternode_outpoint,
      parent_hash,
      outcome,
      signal,
      time,
      sig,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.masternode_outpoint.encode(buf);
    self.parent_hash.encode(buf);
    self.outcome.encode(buf);
    self.signal.encode(buf);
    self.time.encode(buf);
    self.sig.encode(buf);
  }
}

impl_type!(GovVote);

impl Hashable for GovVote {
  type Hash = Hash256;

  /// Computes the canonical vote hash, including dummy padding after the
  /// outpoint for legacy compatibility.
  fn hash(&self) -> Hash256 {
    let mut buf = ArrayBuf::<89>::new();
    // outpoint + dummy padding for legacy hash compat
    self.masternode_outpoint.hash.encode(&mut buf);
    self.masternode_outpoint.index.encode(&mut buf);
    0u8.encode(&mut buf);
    0xFFFF_FFFFu32.encode(&mut buf);
    self.parent_hash.encode(&mut buf);
    self.signal.encode(&mut buf);
    self.outcome.encode(&mut buf);
    self.time.encode(&mut buf);

    Hash256::from_lendian(sha256d::Hash::hash(&buf.into_array()).to_byte_array())
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_govobjvote() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobjvote");
    let items = corpus.entries::<GovVote>("govobjvote", check_wire);
    assert_serde_rt("govobjvote", &items);
  }

  /// A vote of 84 zero bytes before the signature, then `sig_len` bytes.
  fn vote_wire(sig_len: usize) -> Vec<u8> {
    let mut wire = vec![0; 84];
    CompactSize::from(sig_len).encode(&mut wire);
    wire.resize(wire.len() + sig_len, 0xAB);
    wire
  }

  fn bad_len(actual: usize) -> Result<(), DecodeError> {
    Err(DecodeError::BadLen {
      expected: vec![65, 96],
      actual,
    })
  }

  /// The signature length is capped at 96 before the read, and only 65 or 96
  /// bytes are accepted after it.
  #[rstest]
  #[case::empty(0, bad_len(0))]
  #[case::short_compact(64, bad_len(64))]
  #[case::compact(65, Ok(()))]
  #[case::long_compact(66, bad_len(66))]
  #[case::short_bls(95, bad_len(95))]
  #[case::bls(96, Ok(()))]
  #[case::past_bls(97, Err(DecodeError::CompactSizeExceedsLimit { limit: 96, value: 97 }))]
  fn vote_signatures_decode_at_65_or_96_bytes(#[case] len: usize, #[case] expected: Result<(), DecodeError>) {
    let wire = vote_wire(len);
    let decoded = GovVote::decode(&mut wire.as_slice());
    assert_eq!(decoded.clone().map(|_| ()), expected);
    if let Ok(vote) = decoded {
      let mut buf = Vec::new();
      vote.encode(&mut buf);
      assert_eq!(buf, wire);
    }
  }
}
