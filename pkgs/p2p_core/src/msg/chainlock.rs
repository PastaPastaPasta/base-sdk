//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ChainLock and InstantSend lock messages.

use crate::codec::codec_p2p;
use crate::prelude::*;

use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_primitives::{BlockHash, OutPoint, TxHash};
use dash_types::type_id::TypeId;

use core::fmt;

/// A ChainLock signature, the `clsig` payload (Core's `ChainLockSig`).
///
/// Core reads the signature eagerly under its process-wide BLS scheme; the
/// field holds the wire bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ClSig {
  /// Height of the locked block.
  pub height: i32,
  /// Hash of the locked block.
  pub block_hash: BlockHash,
  /// Recovered threshold signature of the signing quorum.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(ClSig {
  height,
  block_hash,
  sig
});

impl fmt::Display for ClSig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "clsig({}:{})", self.height, self.block_hash)
  }
}

/// A deterministic InstantSend lock, the `isdlock` payload (Core's
/// `InstantSendLock`).
///
/// Core reads the signature lazily and hashes the lock over its wire bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct IsdLock {
  /// Lock version; Core reads any value.
  pub version: u8,
  /// Outpoints the locked transaction spends.
  pub inputs: Vec<OutPoint>,
  /// Hash of the locked transaction.
  pub txid: TxHash,
  /// Hash of the block that starts the signing quorum's cycle.
  pub cycle_hash: BlockHash,
  /// Recovered threshold signature of the signing quorum.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_p2p!(IsdLock {
  version,
  inputs,
  txid,
  cycle_hash,
  sig
});

impl fmt::Display for IsdLock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "isdlock({}, {} inputs)", self.txid, self.inputs.len())
  }
}
