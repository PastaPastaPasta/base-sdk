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
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num};

use core::fmt;
use core::time::Duration;

/// Requests specific inventory items from a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(GetData { inventory });

enum_map! {
  /// Inventory object type, Core's `GetDataMsg`.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum InvType, u32, Unknown {
    /// Core's `UNDEFINED`.
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
    /// LLMQ DKG contribution.
    QuorumContrib = 23 => "quorum_contrib",
    /// LLMQ DKG complaint.
    QuorumComplaint = 24 => "quorum_complaint",
    /// LLMQ DKG justification.
    QuorumJustification = 25 => "quorum_justification",
    /// LLMQ DKG premature commitment.
    QuorumPrematureCommitment = 26 => "quorum_premature_commitment",
    /// LLMQ recovered signature.
    QuorumRecoveredSig = 28 => "quorum_recovered_sig",
    /// ChainLock signature.
    ClSig = 29 => "clsig",
    /// InstantSend deterministic lock.
    IsdLock = 31 => "isdlock",
    /// CoinJoin queue entry.
    Dsq = 32 => "dsq",
    /// DIP-0031 platform ban.
    PlatformBan = 33 => "platform_ban",
    /// Version 2 asset unlock, announced by instance hash (v24.0).
    AssetUnlock = 34 => "asset_unlock",
  }
}

impl_num!(InvType, u32);

hash_impl!(InvType);

/// Whether inventory type 34, `MSG_ASSET_UNLOCK`, is known.
///
/// Core v24.0 knows it and carries the object in a `tx`; v23.1.8 does not.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum AssetUnlockInv {
  /// Type 34 is an unknown type, as at v23.1.8.
  Unsupported,
  /// Type 34 is a transaction announcement, as at v24.0.
  Supported,
}

impl InvType {
  /// The command that carries the object, Core's `CInv::GetCommandInternal`.
  ///
  /// `None` is a type Core does not know, which its `inv` handler skips.
  pub fn command(self, asset_unlock: AssetUnlockInv) -> Option<CommandString> {
    Some(match self {
      Self::Tx => CommandString::TX,
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
      Self::AssetUnlock if asset_unlock == AssetUnlockInv::Supported => CommandString::TX,
      Self::AssetUnlock | Self::Error | Self::Unknown(_) => return None,
    })
  }

  /// Whether Core knows the type, `CInv::IsKnownType`.
  pub fn is_known(self, asset_unlock: AssetUnlockInv) -> bool {
    self.command(asset_unlock).is_some()
  }

  /// A transaction announcement, Core's `CInv::IsGenTxMsg`.
  pub fn is_gen_tx(self, asset_unlock: AssetUnlockInv) -> bool {
    match self {
      Self::Tx | Self::Dstx => true,
      Self::AssetUnlock => asset_unlock == AssetUnlockInv::Supported,
      _ => false,
    }
  }

  /// A block request type, Core's `CInv::IsGenBlkMsg`.
  pub fn is_gen_blk(self) -> bool {
    matches!(self, Self::Block | Self::FilteredBlock | Self::CompactBlock)
  }

  /// How long Core waits for an object before asking another peer, its
  /// `GetObjectInterval`.
  pub fn request_interval(self) -> Duration {
    match self {
      Self::QuorumRecoveredSig => Duration::from_secs(15),
      Self::ClSig => Duration::from_secs(5),
      Self::IsdLock => Duration::from_secs(10),
      _ => Duration::from_secs(60),
    }
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

  #[rstest]
  fn corpus_inv() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "inv");
    let items = corpus.entries::<Inv>("inv", check_wire);
    assert_serde_rt("inv", &items);
  }
}
