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

use core::fmt;

/// An error encountered during P2P message decoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum P2pDecodeError {
  /// Underlying consensus decoding error.
  Consensus(String),
  /// V2 short ID does not map to a known message.
  UnknownShortId {
    /// The short ID byte.
    id: u8,
  },
  /// Message payload exceeds the allowed size.
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
  ContentsTooLarge {
    /// Size of the contents, type included, in bytes.
    size: usize,
    /// Maximum allowed size, in bytes.
    max: usize,
  },
  /// A command or long-form type Core's transport refuses, which it drops.
  ///
  /// Core keeps the peer and never hands the message to its handlers.
  InvalidCommand {
    /// The command as received.
    command: CommandString,
  },
  /// V2 packet contents without a type byte, which Core drops.
  EmptyV2Contents,
  /// A V2 long-form type cut short, which Core drops.
  TruncatedV2Type {
    /// Type bytes present, of 12.
    remaining: usize,
  },
  /// A message lists more entries than its handler accepts.
  ///
  /// Core checks the count before reading any entry and penalises the peer.
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
  VersionTail {
    /// The fields decoded before the failure, the optional ones absent.
    head: Box<Version>,
    /// The decode failure in the optional fields.
    error: String,
  },
  /// A field value is outside the valid range.
  InvalidValue {
    /// Brief description of what was invalid.
    field: &'static str,
  },
}

impl From<DecodeError> for P2pDecodeError {
  fn from(e: DecodeError) -> Self {
    Self::Consensus(format!("{e}"))
  }
}

impl fmt::Display for P2pDecodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Consensus(e) => write!(f, "{e}"),
      Self::UnknownShortId { id } => {
        write!(f, "unknown v2 short id: {id}")
      }
      Self::PayloadTooLarge { command, size, max } => {
        write!(f, "{command} payload too large: {size} bytes, max {max}")
      }
      Self::ContentsTooLarge { size, max } => {
        write!(f, "v2 contents too large: {size} bytes, max {max}")
      }
      Self::InvalidCommand { command } => write!(f, "invalid command {:x?}", command.as_bytes()),
      Self::EmptyV2Contents => f.write_str("empty v2 contents"),
      Self::TruncatedV2Type { remaining } => {
        write!(f, "v2 long-form type cut short: {remaining} of 12 bytes")
      }
      Self::TooManyEntries { command, count, max } => {
        write!(f, "{command} lists {count} entries, max {max}")
      }
      Self::VersionTail { error, .. } => write!(f, "version after addr_recv: {error}"),
      Self::InvalidValue { field } => {
        write!(f, "invalid value for {field}")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for P2pDecodeError {}
