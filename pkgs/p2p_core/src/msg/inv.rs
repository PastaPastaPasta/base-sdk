//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages and types.

use crate::codec::codec_p2p;
use crate::command::CommandString;
use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::hash_impl;
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_num};

use core::fmt;

/// Requests specific inventory items from a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(GetData { inventory });

enum_map! {
  /// Inventory object type.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum InvType, u32, Unknown {
    /// Error / not used.
    Error = 0 => "error",
    /// Transaction.
    Tx = 1 => "tx",
    /// Block.
    Block = 2 => "block",
    /// Filtered block (BIP37).
    FilteredBlock = 3 => "filtered_block",
    /// Spork.
    Spork = 6 => "spork",
    /// CoinJoin broadcast transaction.
    Dstx = 16 => "dstx",
    /// Governance object.
    GovernanceObject = 17 => "governance_object",
    /// Governance object vote.
    GovernanceObjectVote = 18 => "governance_object_vote",
    /// Compact block (BIP152).
    CompactBlock = 20 => "compact_block",
    /// LLMQ final commitment.
    QuorumFinalCommitment = 21 => "quorum_final_commitment",
    /// LLMQ contribution.
    QuorumContrib = 23 => "quorum_contrib",
    /// LLMQ complaint.
    QuorumComplaint = 24 => "quorum_complaint",
    /// LLMQ justification.
    QuorumJustification = 25 => "quorum_justification",
    /// LLMQ premature commitment.
    QuorumPrematureCommitment = 26 => "quorum_premature_commitment",
    /// LLMQ recovered signature.
    QuorumRecoveredSig = 28 => "quorum_recovered_sig",
    /// ChainLock signature.
    ClSig = 29 => "cl_sig",
    /// InstantSend deterministic lock.
    IsdLock = 31 => "isd_lock",
    /// CoinJoin queue entry.
    Dsq = 32 => "dsq",
    /// Platform ban (DIP-0031).
    PlatformBan = 33 => "platform_ban",
    /// Version 2 asset unlock, announced by its instance hash.
    AssetUnlock = 34 => "asset_unlock",
  }
}

impl_num!(InvType, u32);

hash_impl!(InvType);

impl InvType {
  /// The command of the message that carries the object, if the type is
  /// known.
  pub fn command(self) -> Option<CommandString> {
    Some(match self {
      Self::Tx | Self::AssetUnlock => CommandString::TX,
      Self::Block => CommandString::BLOCK,
      Self::FilteredBlock => CommandString::MERKLEBLOCK,
      Self::CompactBlock => CommandString::CMPCTBLOCK,
      Self::Spork => CommandString::SPORK,
      Self::Dstx => CommandString::DSTX,
      Self::GovernanceObject => CommandString::GOVOBJ,
      Self::GovernanceObjectVote => CommandString::GOVOBJVOTE,
      Self::QuorumFinalCommitment => CommandString::QFCOMMIT,
      Self::QuorumContrib => CommandString::QCONTRIB,
      Self::QuorumComplaint => CommandString::QCOMPLAINT,
      Self::QuorumJustification => CommandString::QJUSTIFY,
      Self::QuorumPrematureCommitment => CommandString::QPCOMMIT,
      Self::QuorumRecoveredSig => CommandString::QSIGREC,
      Self::ClSig => CommandString::CLSIG,
      Self::IsdLock => CommandString::ISDLOCK,
      Self::Dsq => CommandString::DSQ,
      Self::PlatformBan => CommandString::PLATFORMBAN,
      Self::Error | Self::Unknown(_) => return None,
    })
  }

  /// Whether the object is a transaction.
  pub fn is_tx(self) -> bool {
    matches!(self, Self::Tx | Self::Dstx | Self::AssetUnlock)
  }

  /// Whether the object is a block.
  pub fn is_block(self) -> bool {
    matches!(self, Self::Block | Self::FilteredBlock | Self::CompactBlock)
  }
}

/// An inventory vector: a typed 32-byte hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inventory {
  /// Object type.
  #[cfg_attr(feature = "serde", serde(rename = "type"))]
  pub inv_type: InvType,
  /// Object hash.
  pub hash: Hash256,
}

codec_p2p!(Inventory { inv_type, hash });

impl fmt::Display for Inventory {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.inv_type, self.hash)
  }
}

/// Announces available inventory to a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inv {
  /// Inventory items being announced.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(Inv { inventory });

/// Indicates requested inventory items were not found.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotFound {
  /// Missing inventory items.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(NotFound { inventory });

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct TypeVector {
    #[serde(rename = "type")]
    inv_type: u32,
    command: Option<String>,
    tx: bool,
    block: bool,
  }

  #[rstest]
  fn corpus_inv() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "inv");
    let items = corpus.entries::<Inv>("inv", check_wire);
    assert_serde_rt("inv", &items);
  }

  #[rstest]
  fn inv_type_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "inv");
    for v in corpus.vectors::<TypeVector>("inv_type") {
      let t = InvType::new(v.inv_type);
      let command = t.command();
      assert_eq!(command.as_ref().map(CommandString::as_str), v.command.as_deref(), "{t}");
      assert_eq!((t.is_tx(), t.is_block()), (v.tx, v.block), "{t}");
    }
  }
}
