//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-layer decoding errors.

use crate::command::CommandString;
use crate::msg::Version;
use crate::prelude::*;

use dash_types::codec::DecodeError;
use dash_types::type_id::Unencodable;

/// An error encountered during P2P message decoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq, thiserror::Error, Unencodable)]
pub enum P2pDecodeError {
  /// A field failed to decode, as a Core read throws.
  #[error("{0}")]
  Consensus(DecodeError),
  /// V2 short ID does not map to a known message.
  #[error("unknown v2 short id: {id}")]
  UnknownShortId {
    /// The short ID byte.
    id: u8,
  },
  /// Message payload exceeds the allowed size.
  #[error("{command} payload too large: {size} bytes, max {max}")]
  PayloadTooLarge {
    /// The message's command.
    command: CommandString,
    /// Size of the raw payload, in bytes.
    size: usize,
    /// Maximum allowed size, in bytes.
    max: usize,
  },
  /// V2 packet contents exceed the transport limit.
  ///
  /// Core disconnects on the decrypted length, before reading the type.
  #[error("v2 contents too large: {size} bytes, max {max}")]
  ContentsTooLarge {
    /// Size of the contents, type included, in bytes.
    size: usize,
    /// Maximum allowed size, in bytes.
    max: usize,
  },
  /// A command or long-form type Core's transport refuses, which it drops.
  ///
  /// Core keeps the peer and never hands the message to its handlers.
  #[error("invalid command {:x?}", command.as_bytes())]
  InvalidCommand {
    /// The command as received.
    command: CommandString,
  },
  /// V2 packet contents without a type byte, which Core drops.
  #[error("empty v2 contents")]
  EmptyV2Contents,
  /// A V2 long-form type cut short, which Core drops.
  #[error("v2 long-form type cut short: {remaining} of 12 bytes")]
  TruncatedV2Type {
    /// Type bytes present, of 12.
    remaining: usize,
  },
  /// A payload longer than its handler accepts, below the transport's limit.
  ///
  /// Core's handler checks the length before reading and scores the peer's
  /// misbehaviour at the discouragement threshold: it disconnects and
  /// discourages the peer, except one it may not ban. `PayloadTooLarge`
  /// disconnects at the transport without discouraging.
  #[error("{command} payload over its handler's limit: {size} bytes, max {max}")]
  HandlerPayloadTooLarge {
    /// Wire command name.
    command: &'static str,
    /// Size of the payload, in bytes.
    size: usize,
    /// The handler's limit, in bytes.
    max: usize,
  },
  /// A message lists more entries than its handler accepts.
  ///
  /// Core checks the count before reading any entry and penalises the peer.
  #[error("{command} lists {count} entries, max {max}")]
  TooManyEntries {
    /// Wire command name.
    command: &'static str,
    /// The decoded entry count.
    count: u64,
    /// The handler's limit.
    max: u64,
  },
  /// A `version` whose fields after `addr_recv` fail to decode.
  ///
  /// Core checks the peer's version and services in `head` before it reads
  /// the later fields, and throws only after those checks pass.
  #[error("version after addr_recv: {error}")]
  VersionTail {
    /// The fields decoded before the failure, the optional ones absent.
    head: Box<Version>,
    /// The decode failure in the optional fields.
    error: String,
  },
  /// A field value is outside the valid range.
  #[error("invalid value for {field}")]
  InvalidValue {
    /// Brief description of what was invalid.
    field: &'static str,
  },
}

impl From<DecodeError> for P2pDecodeError {
  fn from(e: DecodeError) -> Self {
    Self::Consensus(e)
  }
}
