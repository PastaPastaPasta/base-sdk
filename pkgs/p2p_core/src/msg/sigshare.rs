//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ signature share messages: session announcements, share inventories
//! and requests, batched shares and single shares.
//!
//! Core reads them only with its signature share manager running, and
//! `qsigshare` only with `SPORK_21_QUORUM_ALL_CONNECTED` active; those gates
//! run before the read. The shares are lazy: Core keeps their wire bytes.

use crate::codec::{
  codec_p2p, dsha256, impl_p2p, read_count_at_most, read_varint_u32, varint_u32_len, write_varint_u32, MsgDecode,
};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::prelude::*;

use dash_num::Hash256;
use dash_params::MAX_LLMQ_SIZE;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_primitives::{hash_impl, DynBitset, LlmqType, QuorumHash};
use dash_types::codec::{read_bytes, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{CompactSize, Numeric};

/// Core's `MAX_MSGS_TOTAL_BATCHED_SIGS`, the largest quorum: the most shares
/// one inventory, batch or `qbsigs` message holds.
pub const MAX_BATCHED_SIGS: usize = MAX_LLMQ_SIZE as usize;

/// Core's `MAX_MSGS_CNT_QSIGSESANN`, the most announcements in a `qsigsesann`.
pub const MAX_SIG_SES_ANNS: usize = 100;

/// Core's `MAX_MSGS_CNT_QSIGSHARES`, the most inventories in a `qsigsinv` or
/// `qgetsigs`.
pub const MAX_SIG_SHARES_INVS: usize = 200;

/// Core's `MAX_MSGS_SIG_SHARES`, the most shares in a `qsigshare`.
pub const MAX_SIG_SHARES: usize = 32;

/// Core's `SignHash`: what a quorum signs for a request, over the type, the
/// quorum, the request's id and the message's hash.
fn sign_hash(llmq_type: LlmqType, quorum_hash: &QuorumHash, id: &Hash256, msg_hash: &Hash256) -> Hash256 {
  let mut buf = Vec::new();
  llmq_type.encode(&mut buf);
  quorum_hash.encode(&mut buf);
  id.encode(&mut buf);
  msg_hash.encode(&mut buf);
  dsha256(&buf)
}

/// A signing session's announcement (Core's `CSigSesAnn`): the session id
/// its sender uses for the request in later messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SigSesAnn {
  /// The sender's session id; a `VARINT` on the wire.
  pub session_id: u32,
  /// Type of the signing quorum.
  pub llmq_type: LlmqType,
  /// Hash of the signing quorum.
  pub quorum_hash: QuorumHash,
  /// Signing request identifier.
  pub id: Hash256,
  /// Hash of the message to sign.
  pub msg_hash: Hash256,
}

impl_p2p!(SigSesAnn);

impl BaseCodec for SigSesAnn {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      session_id: read_varint_u32(data)?,
      llmq_type: LlmqType::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      id: Hash256::decode(data)?,
      msg_hash: Hash256::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    write_varint_u32(self.session_id, buf);
    self.llmq_type.encode(buf);
    self.quorum_hash.encode(buf);
    self.id.encode(buf);
    self.msg_hash.encode(buf);
  }
}

// The hash of the encoding: an identity for maps, not one Core computes or
// keys inventory by.
hash_impl!(SigSesAnn);

impl SigSesAnn {
  /// Core's sign hash of the announced request, which keys the session.
  pub fn sign_hash(&self) -> Hash256 {
    sign_hash(self.llmq_type, &self.quorum_hash, &self.id, &self.msg_hash)
  }
}

/// Reads the bits of an `AUTOBITSET` of `size` bits (Core's
/// `ReadAutoBitSet`): a form byte, then a fixed bitset or the varint offsets
/// of the set bits.
fn read_auto_bitset(data: &mut &[u8], size: u64) -> Result<DynBitset, DecodeError> {
  let len = usize::try_from(size.div_ceil(8)).map_err(|_| DecodeError::Eof {
    needed: usize::MAX,
    remaining: data.len(),
  })?;
  match u8::decode(data)? {
    0 => {
      let bytes = read_bytes(data, len)?;
      if size % 8 != 0 && bytes[len - 1] >> (size % 8) != 0 {
        return Err(DecodeError::InvalidValue {
          expected: vec![0],
          actual: u64::from(bytes[len - 1] >> (size % 8)),
        });
      }
      Ok(DynBitset {
        num_bits: size,
        data: bytes.to_vec(),
      })
    }
    1 => {
      let mut bits = vec![0u8; len];
      let mut last: Option<u64> = None;
      loop {
        let offset = u64::from(read_varint_u32(data)?);
        if offset == 0 {
          break;
        }
        let index = last.map_or(offset - 1, |l| l + offset);
        if index >= size {
          return Err(DecodeError::InvalidValue {
            expected: Vec::new(),
            actual: index,
          });
        }
        bits[(index / 8) as usize] |= 1 << (index % 8);
        last = Some(index);
      }
      Ok(DynBitset {
        num_bits: size,
        data: bits,
      })
    }
    form => Err(DecodeError::InvalidValue {
      expected: vec![0, 1],
      actual: u64::from(form),
    }),
  }
}

/// Writes `bits` as Core's `WriteAutoBitSet`: the varint offsets of the set
/// bits unless the fixed bitset is shorter.
fn write_auto_bitset(bits: &DynBitset, buf: &mut impl EncodeBuf) {
  let mut offsets = Vec::new();
  let mut last = None;
  for index in bits.iter_set_bits() {
    offsets.push(last.map_or(index + 1, |l| index - l) as u32);
    last = Some(index);
  }
  let fixed = (bits.num_bits as usize).div_ceil(8);
  let varints = offsets.iter().map(|&o| varint_u32_len(o)).sum::<usize>() + 1;
  if fixed < varints {
    buf.push(0);
    let mut out = Vec::new();
    bits.encode(&mut out);
    let skip = out.len() - fixed;
    buf.extend_from_slice(&out[skip..]); // nosemgrep: codec-no-raw-extend
  } else {
    buf.push(1);
    for offset in offsets {
      write_varint_u32(offset, buf);
    }
    write_varint_u32(0, buf);
  }
}

/// A signature share inventory (Core's `CSigSharesInv`): the quorum members
/// whose shares the sender has, or asks for, in one session.
///
/// Core writes the bits back in the shorter of its two forms, which the
/// encoder does too, so a share inventory read in the longer form writes
/// back other bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SigSharesInv {
  /// The session id the sender announced; a `VARINT` on the wire.
  pub session_id: u32,
  /// One bit per quorum member, at most [`MAX_BATCHED_SIGS`].
  pub inv: DynBitset,
}

impl_p2p!(SigSharesInv);

impl BaseCodec for SigSharesInv {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let session_id = read_varint_u32(data)?;
    let size = CompactSize::decode_size(data)?.to_base();
    if size > MAX_BATCHED_SIGS as u64 {
      return Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_BATCHED_SIGS,
        value: size,
      });
    }
    Ok(Self {
      session_id,
      inv: read_auto_bitset(data, size)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    write_varint_u32(self.session_id, buf);
    CompactSize::from(self.inv.num_bits).encode(buf);
    write_auto_bitset(&self.inv, buf);
  }
}

// The hash of the encoding: an identity for maps, not one Core computes or
// keys inventory by.
hash_impl!(SigSharesInv);

/// One member's share in a batch.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BatchedSigShare {
  /// Index of the member in the quorum.
  pub quorum_member: u16,
  /// The member's signature share, as read.
  pub sig_share: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(BatchedSigShare {
  quorum_member,
  sig_share
});

/// A batch of shares for one session (Core's `CBatchedSigShares`).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BatchedSigShares {
  /// The session id the sender announced; a `VARINT` on the wire.
  pub session_id: u32,
  /// The shares, at most [`MAX_BATCHED_SIGS`].
  pub sig_shares: Vec<BatchedSigShare>,
}

impl_p2p!(BatchedSigShares);

impl BaseCodec for BatchedSigShares {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let session_id = read_varint_u32(data)?;
    let count = CompactSize::decode_size(data)?.into_len(MAX_BATCHED_SIGS)?;
    let mut sig_shares = Vec::new();
    for _ in 0..count {
      sig_shares.push(BatchedSigShare::decode(data)?);
    }
    Ok(Self { session_id, sig_shares })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    write_varint_u32(self.session_id, buf);
    self.sig_shares.encode(buf);
  }
}

hash_impl!(BatchedSigShares);

/// A member's signature share for a request (Core's `CSigShare`).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SigShare {
  /// Type of the signing quorum.
  pub llmq_type: LlmqType,
  /// Hash of the signing quorum.
  pub quorum_hash: QuorumHash,
  /// Index of the member in the quorum.
  pub quorum_member: u16,
  /// Signing request identifier.
  pub id: Hash256,
  /// Hash of the message signed.
  pub msg_hash: Hash256,
  /// The member's signature share, as read.
  pub sig_share: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(SigShare {
  llmq_type,
  quorum_hash,
  quorum_member,
  id,
  msg_hash,
  sig_share
});

impl SigShare {
  /// Core's sign hash of the request, which with the member keys the share
  /// (`CSigShare::GetKey`).
  pub fn sign_hash(&self) -> Hash256 {
    sign_hash(self.llmq_type, &self.quorum_hash, &self.id, &self.msg_hash)
  }
}

/// Session announcements, the `qsigsesann` payload.
///
/// Like the other message lists here, its handler limits apply in
/// [`MsgDecode::decode_msg`]; [`BaseCodec::decode`] reads any count.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SigSesAnnMsg {
  /// The announcements, at most [`MAX_SIG_SES_ANNS`].
  pub anns: Vec<SigSesAnn>,
}

codec_p2p!(SigSesAnnMsg { anns });

impl MsgDecode for SigSesAnnMsg {
  /// Core refuses more than [`MAX_SIG_SES_ANNS`] before reading any.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let count = read_count_at_most(data, "qsigsesann", MAX_SIG_SES_ANNS)?;
    let anns = (0..count).map(|_| SigSesAnn::decode(data)).collect::<Result<_, _>>()?;
    Ok(Self { anns })
  }
}

/// Share inventories, the `qsigsinv` and `qgetsigs` payloads: the shares the
/// sender has, or those it asks for.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SigSharesInvMsg {
  /// The inventories, at most [`MAX_SIG_SHARES_INVS`].
  pub invs: Vec<SigSharesInv>,
}

codec_p2p!(SigSharesInvMsg { invs });

impl MsgDecode for SigSharesInvMsg {
  /// Core refuses more than [`MAX_SIG_SHARES_INVS`] before reading any.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let count = read_count_at_most(data, "qsigsinv/qgetsigs", MAX_SIG_SHARES_INVS)?;
    let invs = (0..count)
      .map(|_| SigSharesInv::decode(data))
      .collect::<Result<_, _>>()?;
    Ok(Self { invs })
  }
}

/// Batches of shares, the `qbsigs` payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BatchedSigSharesMsg {
  /// The batches, holding at most [`MAX_BATCHED_SIGS`] shares together.
  pub batches: Vec<BatchedSigShares>,
}

codec_p2p!(BatchedSigSharesMsg { batches });

impl MsgDecode for BatchedSigSharesMsg {
  /// Core refuses more than [`MAX_BATCHED_SIGS`] batches before reading any,
  /// and more shares in all once a batch takes them past it.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let count = read_count_at_most(data, "qbsigs", MAX_BATCHED_SIGS)?;
    let mut batches = Vec::new();
    let mut shares = 0;
    for _ in 0..count {
      let batch = BatchedSigShares::decode(data)?;
      shares += batch.sig_shares.len();
      if shares > MAX_BATCHED_SIGS {
        return Err(P2pDecodeError::TooManyEntries {
          command: "qbsigs",
          count: shares as u64,
          max: MAX_BATCHED_SIGS as u64,
        });
      }
      batches.push(batch);
    }
    Ok(Self { batches })
  }
}

/// Single shares, the `qsigshare` payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SigShareMsg {
  /// The shares, at most [`MAX_SIG_SHARES`].
  pub shares: Vec<SigShare>,
}

codec_p2p!(SigShareMsg { shares });

impl MsgDecode for SigShareMsg {
  /// Core refuses more than [`MAX_SIG_SHARES`] before reading any.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let count = read_count_at_most(data, "qsigshare", MAX_SIG_SHARES)?;
    let shares = (0..count).map(|_| SigShare::decode(data)).collect::<Result<_, _>>()?;
    Ok(Self { shares })
  }
}
