//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance messages read as Core's handlers read them: the sync request
//! and a vote's signature size.

use crate::codec::{codec_p2p, read_limited_byte_vec, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::msg::FilterLoad;

use dash_num::Hash256;
use dash_primitives::{GovVote, OutPoint, TxHash, VoteOutcome, VoteSignal};
use dash_types::codec::BaseCodec;
use dash_types::type_id::TypeId;

/// Requests governance objects and votes from a peer, the `govsync`
/// payload.
///
/// When `hash` is zero, the peer responds with all governance
/// objects. When non-zero, it responds with votes for that
/// specific object.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovSync {
  /// Object hash (zero for full sync).
  pub hash: Hash256,
  /// Core's `CBloomFilter`, as `filterload` carries it (an empty one asks
  /// for no filtering). Core penalises data over its limit as a failed
  /// read.
  pub bloom_filter: FilterLoad,
}

codec_p2p!(GovSync { hash, bloom_filter });

/// Core's `COMPACT_SIG_SIZE`, an ECDSA vote signature.
pub const VOTE_ECDSA_SIG_LEN: usize = 65;

/// Core's `BLS_SIG_SIZE`, a BLS vote signature.
pub const VOTE_BLS_SIG_LEN: usize = 96;

impl MsgDecode for GovVote {
  /// A network read of the vote: its signature holds at most
  /// [`VOTE_BLS_SIG_LEN`] bytes, refused before any is read, and then
  /// exactly [`VOTE_ECDSA_SIG_LEN`] or [`VOTE_BLS_SIG_LEN`]. Core penalises
  /// either refusal as a malformed vote. Its other reads (disk, hashing)
  /// take any length, as [`BaseCodec`] does.
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let vote = Self {
      masternode_outpoint: OutPoint::decode(data)?,
      parent_hash: TxHash::decode(data)?,
      outcome: VoteOutcome::decode(data)?,
      signal: VoteSignal::decode(data)?,
      time: i64::decode(data)?,
      sig: read_limited_byte_vec(data, VOTE_BLS_SIG_LEN)?,
    };
    if ![VOTE_ECDSA_SIG_LEN, VOTE_BLS_SIG_LEN].contains(&vote.sig.len()) {
      return Err(P2pDecodeError::InvalidValue {
        field: "governance vote signature size",
      });
    }
    Ok(vote)
  }
}
