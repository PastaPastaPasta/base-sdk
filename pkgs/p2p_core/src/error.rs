//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-layer decoding errors.

use crate::command::CommandString;
use crate::prelude::*;

use dash_types::codec::DecodeError;
use dash_types::type_id::Unencodable;

use core::fmt;

/// An error encountered during P2P message decoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq, thiserror::Error, Unencodable)]
pub enum P2pDecodeError {
  /// Underlying consensus decoding error.
  #[error("{0}")]
  Consensus(String),
  /// Unrecognised 12-byte command string.
  #[error(fmt = fmt_unknown_command)]
  UnknownCommand {
    /// The raw command bytes.
    bytes: [u8; 12],
  },
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
  /// Message carries a payload where none is permitted.
  #[error("{command} must have an empty payload, got {size} bytes")]
  PayloadNotEmpty {
    /// Wire command name.
    command: &'static str,
    /// Size of the raw payload, in bytes.
    size: usize,
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
    Self::Consensus(format!("{e}"))
  }
}

/// Formats `P2pDecodeError::UnknownCommand`, escaping non-printable bytes.
fn fmt_unknown_command(bytes: &[u8; 12], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  f.write_str("unknown command: ")?;
  for &b in bytes.iter().take_while(|&&b| b != 0) {
    if b.is_ascii_graphic() || b == b' ' {
      write!(f, "{}", b as char)?;
    } else {
      write!(f, "\\x{b:02x}")?;
    }
  }
  Ok(())
}
