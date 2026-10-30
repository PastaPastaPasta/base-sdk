//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ DKG messages: contributions, complaints, justifications and
//! premature commitments. [`DkgMessage`] gives the order in which Core's
//! handler and worker take them.

use crate::codec::{codec_p2p, decode_whole, dsha256, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::prelude::*;

use dash_num::Hash256;
use dash_params::{LlmqParams, LlmqType};
use dash_pkc::bls::{
  BlsCtx, BlsDecodeError, BlsEagerPk, BlsEagerSig, BlsEagerSk, BlsIesMultiBytes, BlsPkBytes, BlsSchemeSource,
  BlsSigBytes, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN,
};
use dash_primitives::{DynBitset, QuorumHash, QuorumVvecHash, TxHash};
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{CompactSize, Numeric};

use core::fmt;

/// `llmqType`, `quorumHash` and `proTxHash`, which start every DKG message.
const PREFIX_LEN: u64 = 1 + 32 + 32;

/// A DKG message, read as Core's DKG handler and worker read it.
///
/// A node running DKG sessions (an active masternode) takes a received DKG
/// message in this order, as Core does:
///
/// 1. The handler's gates on the peer and the quorum, each scored apart: a
///    verified masternode peer, a payload holding the type and quorum hash
///    ([`dkg_quorum`]), a known type and a usable quorum.
/// 2. [`DkgMessage::check_payload`]: the quorum's size cap, then the framing
///    walk. Each refusal scores 100.
/// 3. The inventory hash of the payload as received ([`dkg_inventory_hash`]).
/// 4. The GETDATA-response gate: a message the node did not request scores 10
///    and is dropped. It runs after step 2, so an unrequested payload that
///    fails those checks scores 100.
/// 5. The queue of the quorum's session handler; none scores 100. The queue
///    drops, unscored and unread, a hash it has seen and a message over the
///    sender's quota.
/// 6. On the DKG worker, the read: [`MsgDecode::decode_msg`] of the whole
///    payload, then [`DkgMessage::eager`] under the process-wide scheme. A
///    failure of either scores 100.
///
/// Core's other nodes read none of them: an observer ignores them, and a
/// node with no LLMQ role scores each 10.
///
/// [`DkgMessage::decode_checked`] runs step 2 and the whole read in one
/// call, for single-step use such as tests. At intake the node runs the
/// steps apart, so it never reads a message that is unrequested, has no
/// handler or waits in a queue.
///
/// The BLS fields hold the wire bytes. Core signs and checks the fields as
/// its eager read leaves them, so a sign hash is of the message
/// [`DkgMessage::eager`] returns.
pub trait DkgMessage: BaseCodec + MsgDecode {
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
  /// Core runs these after the handler's gates on the peer and the quorum,
  /// and before the inventory hash, the GETDATA-response gate and the read
  /// (steps 2 to 6 in [`DkgMessage`]). Both refusals cost the peer the
  /// discouragement score.
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

  /// [`DkgMessage::check_payload`], then the worker's read of the whole
  /// payload, in one call. A node at intake runs them apart, with the
  /// GETDATA-response gate between them (see [`DkgMessage`]).
  ///
  /// # Errors
  ///
  /// [`DkgMessage::check_payload`]'s, then the read's.
  fn decode_checked(payload: &[u8], params: &LlmqParams) -> Result<Self, P2pDecodeError> {
    Self::check_payload(payload, params)?;
    decode_whole(&mut &payload[..])
  }

  /// Core's eager read of the message's BLS fields (`CBLSWrapper`'s
  /// `Unserialize`) under the process-wide scheme `bls`: the message as
  /// Core's worker holds, writes back and signs it.
  ///
  /// All-zero bytes stay zeros, bytes canonical in the scheme are kept, and
  /// bytes canonical only in the other scheme become zeros. The inventory
  /// hash stays the received payload's ([`dkg_inventory_hash`]), which the
  /// result's [`dash_types::Hashable`] hash can differ from.
  ///
  /// # Errors
  ///
  /// [`BlsDecodeError`] when a field is canonical in neither scheme, where
  /// Core's read throws.
  fn eager(&self, bls: BlsCtx) -> Result<Self, BlsDecodeError>;
}

/// Core's inventory hash of a received DKG message: sha256d of the payload
/// as received, taken before the read. The node keys the GETDATA-response
/// gate, its queues and its relay by it.
pub fn dkg_inventory_hash(payload: &[u8]) -> Hash256 {
  dsha256(payload)
}

/// A public key as Core's eager read leaves it under `bls`.
fn eager_pk(key: &BlsPkBytes, bls: BlsCtx) -> Result<BlsPkBytes, BlsDecodeError> {
  let read = BlsEagerPk::decode(key.as_bytes(), BlsSchemeSource::Global(bls))?;
  Ok(BlsPkBytes::from_bytes(read.to_bytes(bls.scheme())))
}

/// A secret key as Core's eager read leaves it under `bls`.
fn eager_sk(key: &[u8; BLS_SK_LEN], bls: BlsCtx) -> Result<[u8; BLS_SK_LEN], BlsDecodeError> {
  Ok(BlsEagerSk::decode(key, BlsSchemeSource::Global(bls))?.to_bytes(bls.scheme()))
}

/// A signature as Core's eager read leaves it under `bls`.
fn eager_sig(sig: &BlsSigBytes, bls: BlsCtx) -> Result<BlsSigBytes, BlsDecodeError> {
  let read = BlsEagerSig::decode(sig.as_bytes(), BlsSchemeSource::Global(bls))?;
  Ok(BlsSigBytes::from_bytes(read.to_bytes(bls.scheme())))
}

/// Core's ceiling on every DKG payload: `MaxDKGMessageSize` never exceeds
/// it, whatever the quorum's parameters.
const HARD_CEILING: usize = 1 << 20;

/// The impls every DKG message shares: the worker's whole read and a label.
macro_rules! dkg_message {
  ($ty:ident, $command:literal) => {
    impl MsgDecode for $ty {
      /// The worker's whole read, after refusing a payload over 1 MiB as
      /// Core's size cap does for every quorum. The quorum's own cap and the
      /// framing walk are [`DkgMessage::check_payload`]'s.
      fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
        if data.len() > HARD_CEILING {
          return Err(P2pDecodeError::HandlerPayloadTooLarge {
            command: $command,
            size: data.len(),
            max: HARD_CEILING,
          });
        }
        decode_whole(data)
      }
    }

    impl fmt::Display for $ty {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, concat!($command, "({}, {})"), self.quorum_hash, self.pro_tx_hash)
      }
    }
  };
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
    CompactSize::decode(&mut self.0).ok().map(|n| n.to_base())
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

/// A quorum parameter as Core's checks read it.
fn param(value: u16) -> u64 {
  u64::from(value)
}

/// Core's cap on a DKG payload: the message's bound plus slack, at most
/// 1 MiB.
fn capped(bound: u64) -> usize {
  const SLACK: u64 = 1024;
  usize::try_from(bound + SLACK).unwrap_or(usize::MAX).min(HARD_CEILING)
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
  dsha256(&buf)
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
  pub vvec: Vec<BlsPkBytes>,
  /// The secret key shares, one blob per member.
  pub contributions: BlsIesMultiBytes,
  /// The member's signature, as read.
  pub sig: BlsSigBytes,
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
  /// Core's `GetSignHash()`: the message's hash with the signature zeroed,
  /// over the BLS fields as held; Core's is over [`DkgMessage::eager`]'s.
  pub fn sign_hash(&self) -> Hash256 {
    hash_without_sig(self)
  }
}

dkg_message!(DkgContribution, "qcontrib");

impl DkgMessage for DkgContribution {
  const COMMAND: &'static str = "qcontrib";

  fn eager(&self, bls: BlsCtx) -> Result<Self, BlsDecodeError> {
    let shares = &self.contributions;
    Ok(Self {
      llmq_type: self.llmq_type,
      quorum_hash: self.quorum_hash,
      pro_tx_hash: self.pro_tx_hash,
      vvec: self
        .vvec
        .iter()
        .map(|key| eager_pk(key, bls))
        .collect::<Result<_, _>>()?,
      contributions: BlsIesMultiBytes::new(
        eager_pk(shares.ephemeral_pk(), bls)?,
        *shares.iv_seed(),
        shares.blobs().to_vec(),
      ),
      sig: eager_sig(&self.sig, bls)?,
    })
  }

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
  pub sig: BlsSigBytes,
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
  /// Core's `GetSignHash()`: the message's hash with the signature zeroed,
  /// over the BLS fields as held; Core's is over [`DkgMessage::eager`]'s.
  pub fn sign_hash(&self) -> Hash256 {
    hash_without_sig(self)
  }
}

dkg_message!(DkgComplaint, "qcomplaint");

impl DkgMessage for DkgComplaint {
  const COMMAND: &'static str = "qcomplaint";

  fn eager(&self, bls: BlsCtx) -> Result<Self, BlsDecodeError> {
    Ok(Self {
      sig: eager_sig(&self.sig, bls)?,
      ..self.clone()
    })
  }

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

/// A secret key share a justification reveals, Core's
/// `CDKGJustification::Contribution`.
///
/// The share is public once sent, so it is plain bytes rather than a
/// [`dash_pkc::bls::BlsSkBytes`], which never leaves memory unwiped.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DkgRevealedShare {
  /// Index of the member the share is for.
  pub index: u32,
  /// The share's scalar, as read; Core reads it eagerly.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub key: [u8; BLS_SK_LEN],
}

codec_p2p!(DkgRevealedShare { index, key });

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
  pub contributions: Vec<DkgRevealedShare>,
  /// The member's signature, as read.
  pub sig: BlsSigBytes,
}

codec_p2p!(DkgJustification {
  llmq_type,
  quorum_hash,
  pro_tx_hash,
  contributions,
  sig
});

impl DkgJustification {
  /// Core's `GetSignHash()`: the message's hash with the signature zeroed,
  /// over the BLS fields as held; Core's is over [`DkgMessage::eager`]'s.
  pub fn sign_hash(&self) -> Hash256 {
    hash_without_sig(self)
  }
}

dkg_message!(DkgJustification, "qjustify");

impl DkgMessage for DkgJustification {
  const COMMAND: &'static str = "qjustify";

  fn eager(&self, bls: BlsCtx) -> Result<Self, BlsDecodeError> {
    let contributions = self
      .contributions
      .iter()
      .map(|share| {
        Ok(DkgRevealedShare {
          index: share.index,
          key: eager_sk(&share.key, bls)?,
        })
      })
      .collect::<Result<_, _>>()?;
    Ok(Self {
      contributions,
      sig: eager_sig(&self.sig, bls)?,
      ..self.clone()
    })
  }

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
  pub quorum_public_key: BlsPkBytes,
  /// Hash of the quorum's verification vector.
  pub quorum_vvec_hash: QuorumVvecHash,
  /// The member's threshold signature share of the commitment, as read.
  pub quorum_sig: BlsSigBytes,
  /// The member's own signature of the commitment, as read.
  pub sig: BlsSigBytes,
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
  /// and the vector's hash; over the key as held, Core's over
  /// [`DkgMessage::eager`]'s.
  pub fn sign_hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.llmq_type.encode(&mut buf);
    self.quorum_hash.encode(&mut buf);
    self.valid_members.encode(&mut buf);
    self.quorum_public_key.encode(&mut buf);
    self.quorum_vvec_hash.encode(&mut buf);
    dsha256(&buf)
  }
}

dkg_message!(DkgPrematureCommitment, "qpcommit");

impl DkgMessage for DkgPrematureCommitment {
  const COMMAND: &'static str = "qpcommit";

  fn eager(&self, bls: BlsCtx) -> Result<Self, BlsDecodeError> {
    Ok(Self {
      quorum_public_key: eager_pk(&self.quorum_public_key, bls)?,
      quorum_sig: eager_sig(&self.quorum_sig, bls)?,
      sig: eager_sig(&self.sig, bls)?,
      ..self.clone()
    })
  }

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

/// The quorum a DKG payload names, Core's peek before it finds the type's
/// parameters: `None` for a payload shorter than the type and quorum hash,
/// which Core penalises.
pub fn dkg_quorum(payload: &[u8]) -> Option<(LlmqType, QuorumHash)> {
  let mut data = payload;
  let llmq_type = LlmqType::decode(&mut data).ok()?;
  let quorum_hash = QuorumHash::decode(&mut data).ok()?;
  Some((llmq_type, quorum_hash))
}
