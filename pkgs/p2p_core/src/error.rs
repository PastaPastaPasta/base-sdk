//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-layer decoding errors.

use crate::command::CommandString;

use dash_types::codec::DecodeError;
use dash_types::type_id::Unencodable;

use core::fmt;

/// An error encountered during P2P message decoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq, thiserror::Error, Unencodable)]
pub enum P2pDecodeError {
  /// A field failed to decode.
  #[error(transparent)]
  Consensus(#[from] DecodeError),
  /// Unrecognised 12-byte command string.
  #[error(fmt = fmt_unknown_command)]
  UnknownCommand {
    /// The raw command bytes.
    bytes: [u8; 12],
  },
  /// V2 contents end before the message type does.
  #[error("missing command")]
  MissingCommand,
  /// A command its transport refuses, per [`CommandString::is_valid_v1`] or
  /// [`CommandString::is_valid_v2`].
  #[error(fmt = fmt_invalid_command)]
  InvalidCommand {
    /// The command as received.
    command: CommandString,
  },
  /// V2 short ID outside the short ID tables.
  #[error("unknown v2 short id: {id}")]
  UnknownShortId {
    /// The short ID byte.
    id: u8,
  },
  /// Message payload exceeds the allowed size.
  #[error(fmt = fmt_payload_too_large)]
  PayloadTooLarge {
    /// The message's command.
    command: CommandString,
    /// Size of the payload, or of the whole contents for V2, in bytes.
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

/// Formats `P2pDecodeError::UnknownCommand`, escaping non-printable bytes.
fn fmt_unknown_command(bytes: &[u8; 12], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  f.write_str("unknown command: ")?;
  write_command(bytes, f)
}

/// Formats `P2pDecodeError::InvalidCommand`, escaping non-printable bytes.
fn fmt_invalid_command(command: &CommandString, f: &mut fmt::Formatter<'_>) -> fmt::Result {
  f.write_str("invalid command: ")?;
  write_command(command.as_bytes(), f)
}

/// Formats `P2pDecodeError::PayloadTooLarge`, escaping non-printable bytes.
fn fmt_payload_too_large(
  command: &CommandString,
  size: &usize,
  max: &usize,
  f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
  write!(f, "payload too large: {size} bytes, max {max}, command ")?;
  write_command(command.as_bytes(), f)
}

/// Writes command bytes up to the first NUL, escaping non-printable bytes.
fn write_command(bytes: &[u8; 12], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  for &b in bytes.iter().take_while(|&&b| b != 0) {
    if b.is_ascii_graphic() || b == b' ' {
      write!(f, "{}", b as char)?;
    } else {
      write!(f, "\\x{b:02x}")?;
    }
  }
  Ok(())
}
