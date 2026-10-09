//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash primitive types for consensus encoding and decoding.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod block;
mod codec;
mod gov;
mod payload;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod support;
mod transaction;
mod types;

#[doc(hidden)]
pub mod __private {
  pub use bitcoin_hashes;
  pub use dash_num;
  pub use dash_types;
}
#[cfg(feature = "serde")]
pub mod serialize;

pub use block::{
  Block, BlockHash, BlockHeader, BlockInvalid, MerkleRoot, MAX_DIP0001_BLOCK_SIZE, MAX_LEGACY_BLOCK_SIZE,
};
pub use gov::{
  GovData, GovObject, GovObjectType, GovVote, Proposal, ProposalInvalid, Trigger, VoteOutcome, VoteSignal,
};
pub use payload::{
  commitment_bls_scheme, protx_bls_scheme, AssetLock, AssetLockInvalid, AssetUnlock, AssetUnlockInvalid, CbTxInvalid,
  CoinbaseCommitment, CollateralShare, Commitment, CommitmentInvalid, CompactSig, FinalCommitment, InputsHash,
  MnHardFork, MnHardForkInvalid, MnType, PayloadDecode, PayloadError, PayloadInvalid, PayoutShare, PlatformNodeId,
  ProDisTx, ProRegTx, ProTxInvalid, ProUpRegTx, ProUpRevTx, ProUpServTx, ProUpShareTx, ProUpSharedRegTx, QuorumHash,
  QuorumVvecHash, SpecialPayload, TxType, COMPACT_SIG_LEN, VERSIONBITS_NUM_BITS,
};
pub use support::{DynBitset, DynBitsetIterator, LlmqType, RevocationReason};
pub use transaction::{
  OutPoint, Transaction, TxHash, TxIn, TxInvalid, TxOut, MAX_COINBASE_SCRIPT_SIZE, MAX_TX_EXTRA_PAYLOAD,
};
pub use types::{
  is_bad_port, AddrV1, AddrV2, NIEntry, NIEntryCode, NIError, NIPurpose, NITrait, NetAddr, NetAddrError, NetInfo,
  NetInfoV1, NetInfoV2, NetworkType, ServiceV1, ServiceV2,
};
