//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ DKG messages: contributions, complaints, justifications and
//! premature commitments.
//!
//! Core's handler checks a DKG payload against its quorum's parameters
//! before reading it: a size cap, then a walk over its framing
//! ([`DkgMessage::check_payload`]). A DKG worker then reads the message
//! ([`MsgDecode`]), refusing bytes after it. The BLS fields hold the wire
//! bytes: Core reads them eagerly under its process-wide scheme, which the
//! node applies.

use crate::codec::{codec_p2p, decode_whole, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_params::LlmqParams;
use dash_pkc::bls::{BlsIesMultiBytes, BlsPkBytes, BlsScIetf, BlsSigBytes, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN};
use dash_primitives::{DynBitset, LlmqType, QuorumHash, QuorumVvecHash, TxHash};
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{CompactSize, Numeric};

use core::fmt;

/// `llmqType`, `quorumHash` and `proTxHash`, which start every DKG message.
const PREFIX_LEN: u64 = 1 + 32 + 32;

/// A DKG message, read as Core's DKG handler and worker read it.
pub trait DkgMessage: MsgDecode {
  /// The message's command.
  const COMMAND: &'static str;

  /// Core's `MaxDKGMessageSize`: the largest payload of this message the
  /// handler accepts for a quorum with `params`.
  fn max_size(params: &LlmqParams) -> usize;

  /// Core's framing walk (`Check*WireStructure`): `true` when the counts fit
  /// `params` and the payload ends with the message. A cut-short payload is
  /// `false`, as Core catches its throw.
  fn framing_fits(payload: &[u8], params: &LlmqParams) -> bool;

  /// Core's checks of a DKG payload before any read: its size against
  /// [`DkgMessage::max_size`], then its framing against `params`, the
  /// parameters of the quorum type in its first byte.
  ///
  /// Core runs these after finding the type's parameters and the quorum,
  /// and before reading the message ([`MsgDecode::decode_msg`]), which fails
  /// for bytes after it. Both refusals cost the peer the discouragement
  /// score.
  ///
  /// # Errors
  ///
  /// [`P2pDecodeError::HandlerPayloadTooLarge`] above the size cap, or
  /// [`P2pDecodeError::DkgFraming`] where the walk refuses.
  fn check_payload(payload: &[u8], params: &LlmqParams) -> Result<(), P2pDecodeError> {
    let max = Self::max_size(params);
    if payload.len() > max {
      return Err(P2pDecodeError::HandlerPayloadTooLarge {
        command: Self::COMMAND,
        size: payload.len(),
        max,
      });
    }
    if !Self::framing_fits(payload, params) {
      return Err(P2pDecodeError::DkgFraming { command: Self::COMMAND });
    }
    Ok(())
  }
}

/// A position in a payload, as Core's framing walk reads it.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
struct Walk<'a>(&'a [u8]);

impl Walk<'_> {
  /// `ds.ignore(n)`: fails past the end.
  fn ignore(&mut self, n: u64) -> Option<()> {
    let n = usize::try_from(n).ok().filter(|&n| n <= self.0.len())?;
    self.0 = &self.0[n..];
    Some(())
  }

  /// `ReadCompactSize(ds)`, with Core's `MAX_SIZE` range check.
  fn count(&mut self) -> Option<u64> {
    CompactSize::decode_size(&mut self.0).ok().map(|n| n.to_base())
  }

  /// Core's `ReadBoundedDynBitset`: a bit count above `max` fails, then the
  /// bits read as `DYNBITSET`'s do, padding bits refused.
  fn dyn_bitset(&mut self, max: u64) -> Option<u64> {
    let bits = self.count()?;
    if bits > max {
      return None;
    }
    let len = bits.div_ceil(8);
    let bytes = self.0.get(..usize::try_from(len).ok()?)?;
    if bits % 8 != 0 && bytes[bytes.len() - 1] >> (bits % 8) != 0 {
      return None;
    }
    self.ignore(len).map(|()| bits)
  }
}

/// Walks `payload` with `steps`: whether every step passed and the payload
/// ended with them. A count outside the quorum's bounds fails its step.
fn walked(payload: &[u8], steps: impl FnOnce(&mut Walk<'_>) -> Option<()>) -> bool {
  let mut walk = Walk(payload);
  steps(&mut walk).is_some() && walk.0.is_empty()
}

/// A quorum parameter as Core's checks read it: negative counts as zero.
fn param(value: i32) -> u64 {
  u64::try_from(value).unwrap_or(0)
}

/// Core's cap on a DKG payload: the message's bound plus slack, at most
/// 1 MiB.
fn capped(bound: u64) -> usize {
  const SLACK: u64 = 1024;
  const HARD_CEILING: u64 = 1 << 20;
  usize::try_from((bound + SLACK).min(HARD_CEILING)).unwrap_or(usize::MAX)
}

/// The largest CompactSize `MaxDKGMessageSize` allows for a count.
const COMPACT: u64 = 5;

/// `CHashWriter` over `obj` with its signature written as Core's default
/// `CBLSSignature`, all zeros.
fn hash_without_sig(obj: &impl BaseCodec) -> Hash256 {
  let mut buf = Vec::new();
  obj.encode(&mut buf);
  let at = buf.len() - BLS_SIG_LEN;
  buf[at..].fill(0);
  Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
}

/// A member's DKG contribution, the `qcontrib` payload (Core's
/// `CDKGContribution`): its verification vector and its secret key shares,
/// each encrypted to the member it is for.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DkgContribution {
  /// Type of the quorum.
  pub llmq_type: LlmqType,
  /// Hash of the quorum's base block.
  pub quorum_hash: QuorumHash,
  /// Registration transaction hash of the contributing member.
  pub pro_tx_hash: TxHash,
  /// The member's verification vector, as read.
  pub vvec: Vec<BlsPkBytes<BlsScIetf>>,
  /// The secret key shares, one blob per member.
  pub contributions: BlsIesMultiBytes<BlsScIetf>,
  /// The member's signature, as read.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(DkgContribution {
  llmq_type,
  quorum_hash,
  pro_tx_hash,
  vvec,
  contributions,
  sig
});

impl DkgContribution {
  /// Core's `GetSignHash()`: the message's hash with the signature zeroed.
  pub fn sign_hash(&self) -> Hash256 {
    hash_without_sig(self)
  }
}

impl MsgDecode for DkgContribution {
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    decode_whole(data)
  }
}

impl DkgMessage for DkgContribution {
  const COMMAND: &'static str = "qcontrib";

  fn max_size(params: &LlmqParams) -> usize {
    const BLOB: u64 = COMPACT + 128;
    let pk = BLS_PK_LEN as u64;
    capped(
      PREFIX_LEN
        + (COMPACT + param(params.threshold) * pk)
        + (pk + 32 + COMPACT + param(params.size) * BLOB)
        + BLS_SIG_LEN as u64,
    )
  }

  fn framing_fits(payload: &[u8], params: &LlmqParams) -> bool {
    walked(payload, |walk| {
      walk.ignore(PREFIX_LEN)?;
      let threshold = param(params.threshold);
      (walk.count()? == threshold).then_some(())?;
      walk.ignore(threshold * BLS_PK_LEN as u64)?;
      walk.ignore(BLS_PK_LEN as u64 + 32)?;
      let blobs = walk.count()?;
      (param(params.min_size)..=param(params.size))
        .contains(&blobs)
        .then_some(())?;
      for _ in 0..blobs {
        let len = walk.count()?;
        walk.ignore(len)?;
      }
      walk.ignore(BLS_SIG_LEN as u64)?;
      Some(())
    })
  }
}

impl fmt::Display for DkgContribution {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qcontrib({}, {})", self.quorum_hash, self.pro_tx_hash)
  }
}

/// A member's complaints, the `qcomplaint` payload (Core's `CDKGComplaint`):
/// the members it found bad and those whose contribution it complains of.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DkgComplaint {
  /// Type of the quorum.
  pub llmq_type: LlmqType,
  /// Hash of the quorum's base block.
  pub quorum_hash: QuorumHash,
  /// Registration transaction hash of the complaining member.
  pub pro_tx_hash: TxHash,
  /// Members found bad, by index.
  pub bad_members: DynBitset,
  /// Members whose contribution is complained of, by index.
  pub complain_for_members: DynBitset,
  /// The member's signature, as read.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(DkgComplaint {
  llmq_type,
  quorum_hash,
  pro_tx_hash,
  bad_members,
  complain_for_members,
  sig
});

impl DkgComplaint {
  /// Core's `GetSignHash()`: the message's hash with the signature zeroed.
  pub fn sign_hash(&self) -> Hash256 {
    hash_without_sig(self)
  }
}

impl MsgDecode for DkgComplaint {
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    decode_whole(data)
  }
}

impl DkgMessage for DkgComplaint {
  const COMMAND: &'static str = "qcomplaint";

  fn max_size(params: &LlmqParams) -> usize {
    capped(PREFIX_LEN + 2 * (COMPACT + param(params.size).div_ceil(8)) + BLS_SIG_LEN as u64)
  }

  fn framing_fits(payload: &[u8], params: &LlmqParams) -> bool {
    walked(payload, |walk| {
      walk.ignore(PREFIX_LEN)?;
      let size = param(params.size);
      let bad = walk.dyn_bitset(size)?;
      let complain_for = walk.dyn_bitset(size)?;
      (bad == complain_for).then_some(())?;
      walk.ignore(BLS_SIG_LEN as u64)?;
      Some(())
    })
  }
}

impl fmt::Display for DkgComplaint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qcomplaint({}, {})", self.quorum_hash, self.pro_tx_hash)
  }
}

/// A secret key share a justification reveals, Core's
/// `CDKGJustification::Contribution`.
///
/// The share is public once sent, so it is plain bytes rather than a
/// [`dash_pkc::bls::BlsSkBytes`], which never leaves memory unwiped.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DkgShare {
  /// Index of the member the share is for.
  pub index: u32,
  /// The share's scalar, as read; Core reads it eagerly.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub key: [u8; BLS_SK_LEN],
}

codec_p2p!(DkgShare { index, key });

/// A member's justification, the `qjustify` payload (Core's
/// `CDKGJustification`): the shares it was complained of, revealed.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DkgJustification {
  /// Type of the quorum.
  pub llmq_type: LlmqType,
  /// Hash of the quorum's base block.
  pub quorum_hash: QuorumHash,
  /// Registration transaction hash of the justifying member.
  pub pro_tx_hash: TxHash,
  /// The revealed shares.
  pub contributions: Vec<DkgShare>,
  /// The member's signature, as read.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(DkgJustification {
  llmq_type,
  quorum_hash,
  pro_tx_hash,
  contributions,
  sig
});

impl DkgJustification {
  /// Core's `GetSignHash()`: the message's hash with the signature zeroed.
  pub fn sign_hash(&self) -> Hash256 {
    hash_without_sig(self)
  }
}

impl MsgDecode for DkgJustification {
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    decode_whole(data)
  }
}

impl DkgMessage for DkgJustification {
  const COMMAND: &'static str = "qjustify";

  fn max_size(params: &LlmqParams) -> usize {
    capped(PREFIX_LEN + (COMPACT + param(params.size) * (4 + BLS_SK_LEN as u64)) + BLS_SIG_LEN as u64)
  }

  fn framing_fits(payload: &[u8], params: &LlmqParams) -> bool {
    walked(payload, |walk| {
      walk.ignore(PREFIX_LEN)?;
      let shares = walk.count()?;
      (shares <= param(params.size)).then_some(())?;
      walk.ignore(shares * (4 + BLS_SK_LEN as u64))?;
      walk.ignore(BLS_SIG_LEN as u64)?;
      Some(())
    })
  }
}

impl fmt::Display for DkgJustification {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qjustify({}, {})", self.quorum_hash, self.pro_tx_hash)
  }
}

/// A member's premature commitment, the `qpcommit` payload (Core's
/// `CDKGPrematureCommitment`): the valid members it saw and the quorum key it
/// derived, which final commitments aggregate.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DkgPrematureCommitment {
  /// Type of the quorum.
  pub llmq_type: LlmqType,
  /// Hash of the quorum's base block.
  pub quorum_hash: QuorumHash,
  /// Registration transaction hash of the committing member.
  pub pro_tx_hash: TxHash,
  /// Members the committing member counts valid, by index.
  pub valid_members: DynBitset,
  /// The quorum public key, as read.
  pub quorum_public_key: BlsPkBytes<BlsScIetf>,
  /// Hash of the quorum's verification vector.
  pub quorum_vvec_hash: QuorumVvecHash,
  /// The member's threshold signature share of the commitment, as read.
  pub quorum_sig: BlsSigBytes<BlsScIetf>,
  /// The member's own signature of the commitment, as read.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(DkgPrematureCommitment {
  llmq_type,
  quorum_hash,
  pro_tx_hash,
  valid_members,
  quorum_public_key,
  quorum_vvec_hash,
  quorum_sig,
  sig
});

impl DkgPrematureCommitment {
  /// Core's `GetSignHash()`, `BuildCommitmentHash`: the hash both
  /// signatures sign, over the type, the quorum, the valid members, the key
  /// and the vector's hash.
  pub fn sign_hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.llmq_type.encode(&mut buf);
    self.quorum_hash.encode(&mut buf);
    self.valid_members.encode(&mut buf);
    self.quorum_public_key.encode(&mut buf);
    self.quorum_vvec_hash.encode(&mut buf);
    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl MsgDecode for DkgPrematureCommitment {
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    decode_whole(data)
  }
}

impl DkgMessage for DkgPrematureCommitment {
  const COMMAND: &'static str = "qpcommit";

  fn max_size(params: &LlmqParams) -> usize {
    capped(PREFIX_LEN + (COMPACT + param(params.size).div_ceil(8)) + BLS_PK_LEN as u64 + 32 + 2 * BLS_SIG_LEN as u64)
  }

  fn framing_fits(payload: &[u8], params: &LlmqParams) -> bool {
    walked(payload, |walk| {
      walk.ignore(PREFIX_LEN)?;
      walk.dyn_bitset(param(params.size))?;
      walk.ignore(BLS_PK_LEN as u64 + 32 + 2 * BLS_SIG_LEN as u64)?;
      Some(())
    })
  }
}

impl fmt::Display for DkgPrematureCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "qpcommit({}, {})", self.quorum_hash, self.pro_tx_hash)
  }
}

/// The quorum a DKG payload names, Core's peek before it finds the type's
/// parameters: `None` for a payload shorter than the type and quorum hash,
/// which Core penalises.
pub fn dkg_quorum(payload: &[u8]) -> Option<(LlmqType, QuorumHash)> {
  let mut data = payload;
  let llmq_type = LlmqType::decode(&mut data).ok()?;
  let quorum_hash = QuorumHash::decode(&mut data).ok()?;
  Some((llmq_type, quorum_hash))
}
