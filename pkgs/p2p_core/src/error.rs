//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-layer decoding errors.

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
    /// Wire command name.
    command: &'static str,
    /// Size of the raw payload, in bytes.
    size: usize,
    /// Maximum allowed size, in bytes.
    max: usize,
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
      Self::TooManyEntries { command, count, max } => {
        write!(f, "{command} lists {count} entries, max {max}")
      }
      Self::InvalidValue { field } => {
        write!(f, "invalid value for {field}")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for P2pDecodeError {}
