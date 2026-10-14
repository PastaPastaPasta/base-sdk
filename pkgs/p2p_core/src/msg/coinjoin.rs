//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinJoin messages: session requests, entries, the final transaction and
//! its signatures, status updates, queues and broadcast transactions.
//!
//! Core reads these and logs a failed read without penalising the peer; it
//! ignores bytes after a message. Its handlers run only once the chain is
//! synced. The entry and signature counts are bounded by the chain's pool
//! size ([`max_pool_entries`]), which the node checks.
//!
//! The types' [`Hashable`](dash_types::Hashable) hash is of the message as
//! written; it is a Core key only for [`DsQueue`] (Core keys a [`DsTx`] by
//! its transaction's hash).

use crate::codec::{codec_p2p, dsha256, impl_p2p, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::prelude::*;
use crate::version::ProtocolVersion;

use dash_num::Hash256;
use dash_params::ChainParams;
use dash_primitives::{hash_impl, Transaction, TxHash, TxIn, TxOut};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{CompactSize, CoreBool, Numeric};

/// Core's `COINJOIN_ENTRY_MAX_SIZE`, the most inputs or outputs one
/// participant may add.
pub const COINJOIN_ENTRY_MAX_SIZE: usize = 9;

/// Core's `GetMaxPoolInputOutputCount()`: the most inputs or outputs a pool
/// holds, which bounds a `dsi` entry's lists (Core throws past it) and a
/// `dss` list (Core answers `ERR_MAXIMUM`).
pub fn max_pool_entries(params: &ChainParams) -> usize {
  usize::try_from(params.pool_max_participants).unwrap_or(0) * COINJOIN_ENTRY_MAX_SIZE
}

/// A request to join a mixing session, the `dsa` payload (Core's
/// `CCoinJoinAccept`).
///
/// Written with its flags when they are `Some`: a peer at
/// [`ProtocolVersion::COINJOIN_REBALANCE`] or later needs them (Core fails
/// its read without), and one before it reads none. Core compares a
/// request without flags as one with flags 0.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DsAccept {
  /// The denomination, as Core's denomination bits.
  pub denom: i32,
  /// The collateral transaction.
  pub collateral: Transaction,
  /// The rebalance flags, sent at [`ProtocolVersion::COINJOIN_REBALANCE`]
  /// and later only; any byte.
  pub flags: Option<u8>,
}

impl_p2p!(DsAccept);

impl DsAccept {
  fn read(data: &mut &[u8], has_flags: impl FnOnce(&[u8]) -> bool) -> Result<Self, DecodeError> {
    let denom = i32::decode(data)?;
    let collateral = Transaction::decode(data)?;
    let flags = if has_flags(data) { Some(u8::decode(data)?) } else { None };
    Ok(Self {
      denom,
      collateral,
      flags,
    })
  }
}

impl BaseCodec for DsAccept {
  /// Reads the flags when a byte follows the transaction; a peer's message
  /// is read at its version ([`MsgDecode::decode_msg`]).
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::read(data, |rest| !rest.is_empty())
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.denom.encode(buf);
    self.collateral.encode(buf);
    if let Some(flags) = self.flags {
      flags.encode(buf);
    }
  }
}

hash_impl!(DsAccept);

impl MsgDecode for DsAccept {
  /// The flags byte at the negotiated version, as Core's
  /// `SERIALIZE_METHODS` reads it.
  fn decode_msg(data: &mut &[u8], ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    Ok(Self::read(data, |_| {
      ctx.version >= ProtocolVersion::COINJOIN_REBALANCE
    })?)
  }
}

/// A participant's inputs and outputs, the `dsi` payload (Core's
/// `CCoinJoinEntry`). The collateral sits between the two lists.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DsEntry {
  /// The inputs to mix.
  pub inputs: Vec<TxIn>,
  /// The collateral transaction.
  pub collateral: Transaction,
  /// The mixed outputs.
  pub outputs: Vec<TxOut>,
}

codec_p2p!(DsEntry {
  inputs,
  collateral,
  outputs
});

impl MsgDecode for DsEntry {}

impl DsEntry {
  /// Whether Core reads both lists: each at most [`max_pool_entries`], which
  /// Core checks against each count before reading the list. Past it Core
  /// fails the read, as for any other failure.
  pub fn fits_pool(&self, params: &ChainParams) -> bool {
    let max = max_pool_entries(params);
    self.inputs.len() <= max && self.outputs.len() <= max
  }
}

/// The transaction to sign, the `dsf` payload.
///
/// Core's client hands one stream to each of its sessions mixing on the
/// sending masternode in turn, and each reads a message from where the
/// last stopped (`dsf`, `dsc` and `dssu` alike): a payload holding two
/// messages updates two sessions. The node's port reads them so.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DsFinalTx {
  /// The session.
  pub session_id: i32,
  /// The final transaction.
  pub tx: Transaction,
}

codec_p2p!(DsFinalTx { session_id, tx });

impl MsgDecode for DsFinalTx {}

/// A participant's signed inputs of the final transaction, the `dss`
/// payload.
///
/// Core compares the count with [`max_pool_entries`] before reading any
/// input and answers a larger one (`ERR_MAXIMUM`) where it only logs a
/// failed read: the node runs [`DsSignedInputs::check_payload`] first.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DsSignedInputs {
  /// The inputs with their signatures.
  pub inputs: Vec<TxIn>,
}

codec_p2p!(DsSignedInputs { inputs });

impl MsgDecode for DsSignedInputs {}

impl DsSignedInputs {
  /// Core's count check before the read: [`P2pDecodeError::TooManyEntries`]
  /// past [`max_pool_entries`], which Core answers with `ERR_MAXIMUM`, and
  /// otherwise a count that does not read (Core logs it).
  pub fn check_payload(payload: &[u8], params: &ChainParams) -> Result<(), P2pDecodeError> {
    let count = CompactSize::decode_size(&mut &payload[..])?.to_base();
    let max = max_pool_entries(params) as u64;
    if count > max {
      return Err(P2pDecodeError::TooManyEntries {
        command: "dss",
        count,
        max,
      });
    }
    Ok(())
  }
}

/// The end of a session, the `dsc` payload; read per session as
/// [`DsFinalTx`] is.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DsComplete {
  /// The session.
  pub session_id: i32,
  /// Core's `PoolMessage`, as read; its client ignores values out of range.
  pub message: i32,
}

codec_p2p!(DsComplete { session_id, message });

impl MsgDecode for DsComplete {}

/// A session's status, the `dssu` payload (Core's
/// `CCoinJoinStatusUpdate`; its entry count is not sent); read per session
/// as [`DsFinalTx`] is.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DsStatusUpdate {
  /// The session.
  pub session_id: i32,
  /// Core's `PoolState`, as read.
  pub state: i32,
  /// Core's `PoolStatusUpdate`, as read.
  pub status_update: i32,
  /// Core's `PoolMessage`, as read.
  pub message_id: i32,
}

codec_p2p!(DsStatusUpdate {
  session_id,
  state,
  status_update,
  message_id
});

impl MsgDecode for DsStatusUpdate {}

/// A masternode's mixing queue, the `dsq` payload (Core's
/// `CCoinJoinQueue`).
///
/// Core reads any non-zero `ready` byte as `true` and hashes and signs the
/// queue as it writes it back, with `0x01`. Its `GetHash()`, which keys the
/// queue's inventory, is [`Hashable::hash`](dash_types::Hashable::hash), of
/// the queue as written; [`DsQueue::signature_hash`] leaves out the
/// signature.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DsQueue {
  /// The denomination, as Core's denomination bits.
  pub denom: i32,
  /// Registration transaction hash of the masternode.
  pub pro_tx_hash: TxHash,
  /// The queue's time, in seconds.
  pub time: i64,
  /// Whether the session is ready to mix.
  pub ready: CoreBool,
  /// The masternode's BLS signature, as read.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

codec_p2p!(DsQueue {
  denom,
  pro_tx_hash,
  time,
  ready,
  sig
});

impl MsgDecode for DsQueue {}

impl DsQueue {
  /// Core's `GetSignatureHash()`: the queue as written, without the
  /// signature.
  pub fn signature_hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.denom.encode(&mut buf);
    self.pro_tx_hash.encode(&mut buf);
    self.time.encode(&mut buf);
    self.ready.encode(&mut buf);
    dsha256(&buf)
  }
}

/// A masternode-signed mixed transaction, the `dstx` payload (Core's
/// `CCoinJoinBroadcastTx`). Core keys it by the transaction's hash
/// (`tx.hash()`), not by [`Hashable::hash`](dash_types::Hashable::hash).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DsTx {
  /// The mixed transaction.
  pub tx: Transaction,
  /// Registration transaction hash of the masternode.
  pub pro_tx_hash: TxHash,
  /// The masternode's BLS signature, as read.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
  /// The signature's time, in seconds.
  pub sig_time: i64,
}

codec_p2p!(DsTx {
  tx,
  pro_tx_hash,
  sig,
  sig_time
});

impl MsgDecode for DsTx {}

impl DsTx {
  /// Core's `GetSignatureHash()`: the message as written without the
  /// signature, its time included.
  pub fn signature_hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.tx.encode(&mut buf);
    self.pro_tx_hash.encode(&mut buf);
    self.sig_time.encode(&mut buf);
    dsha256(&buf)
  }
}
