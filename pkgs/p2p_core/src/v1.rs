//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V1 message framing.

use crate::codec::MAX_P2P_PAYLOAD_SIZE;
use crate::command::CommandString;
use crate::magic::Magic;
use crate::msg::P2pMsg;
use crate::prelude::*;

use dash_types::codec::BaseCodec;
use dash_types::type_id::Unencodable;

use bitcoin_hashes::sha256d;

use core::fmt;

/// The 24-byte header in front of every V1 payload.
///
/// Wire format: magic, 12-byte command, `u32` payload length, then the
/// first four bytes of the payload's SHA256d.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct V1Header {
  /// Network magic, Core's `pchMessageStart`.
  pub magic: Magic,
  /// The message's command.
  pub command: CommandString,
  /// Payload length in bytes.
  pub length: u32,
  /// The payload's checksum.
  pub checksum: [u8; 4],
}

/// Why Core's V1 transport refuses a message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum V1FrameError {
  /// The header's magic is not the network's; Core disconnects.
  WrongMagic {
    /// The magic received.
    magic: Magic,
  },
  /// The header announces a payload above 3 MiB; Core disconnects before
  /// reading it.
  TooLarge {
    /// The announced length.
    length: u32,
  },
  /// The payload does not match the checksum; Core drops the message and
  /// keeps the peer.
  BadChecksum,
  /// The command has bytes Core's `IsCommandValid` refuses; Core drops the
  /// message and keeps the peer.
  InvalidCommand,
}

impl V1FrameError {
  /// Whether Core disconnects the peer rather than dropping the message.
  pub const fn disconnects(self) -> bool {
    matches!(self, Self::WrongMagic { .. } | Self::TooLarge { .. })
  }
}

impl fmt::Display for V1FrameError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::WrongMagic { magic } => write!(f, "wrong message start {magic:?}"),
      Self::TooLarge { length } => write!(f, "message too large: {length} bytes"),
      Self::BadChecksum => f.write_str("wrong checksum"),
      Self::InvalidCommand => f.write_str("invalid message type"),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for V1FrameError {}

impl V1Header {
  /// Bytes in a header, Core's `CMessageHeader::HEADER_SIZE`.
  pub const SIZE: usize = 24;

  /// Reads a header; any 24 bytes form one.
  pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
    let mut magic = [0u8; 4];
    let mut command = [0u8; 12];
    let mut length = [0u8; 4];
    let mut checksum = [0u8; 4];
    magic.copy_from_slice(&bytes[..4]);
    command.copy_from_slice(&bytes[4..16]);
    length.copy_from_slice(&bytes[16..20]);
    checksum.copy_from_slice(&bytes[20..]);
    Self {
      magic: Magic::from_bytes(magic),
      command: CommandString::from_bytes(command),
      length: u32::from_le_bytes(length),
      checksum,
    }
  }

  /// Writes the header.
  pub fn to_bytes(&self) -> [u8; Self::SIZE] {
    let mut out = [0u8; Self::SIZE];
    out[..4].copy_from_slice(self.magic.as_bytes());
    out[4..16].copy_from_slice(self.command.as_bytes());
    out[16..20].copy_from_slice(&self.length.to_le_bytes());
    out[20..].copy_from_slice(&self.checksum);
    out
  }

  /// The header for `payload` under `command`.
  ///
  /// # Errors
  ///
  /// Returns `TooLarge` for a payload Core would refuse to read.
  pub fn for_payload(magic: Magic, command: CommandString, payload: &[u8]) -> Result<Self, V1FrameError> {
    if payload.len() > MAX_P2P_PAYLOAD_SIZE {
      return Err(V1FrameError::TooLarge {
        length: u32::try_from(payload.len()).unwrap_or(u32::MAX),
      });
    }
    Ok(Self {
      magic,
      command,
      // At most 3 MiB, checked above.
      length: payload.len() as u32,
      checksum: checksum(payload),
    })
  }

  /// Core's checks once the header is in, before any payload byte
  /// (`V1Transport::readHeader`): the magic, then the length.
  ///
  /// # Errors
  ///
  /// Returns `WrongMagic` or `TooLarge`, on which Core disconnects.
  pub fn check(&self, magic: Magic) -> Result<(), V1FrameError> {
    if self.magic != magic {
      return Err(V1FrameError::WrongMagic { magic: self.magic });
    }
    if self.length as usize > MAX_P2P_PAYLOAD_SIZE {
      return Err(V1FrameError::TooLarge { length: self.length });
    }
    Ok(())
  }

  /// Core's checks once the payload is in (`V1Transport::GetReceivedMessage`):
  /// the checksum, then the command bytes.
  ///
  /// # Errors
  ///
  /// Returns `BadChecksum` or `InvalidCommand`, on which Core drops the
  /// message and keeps the peer.
  pub fn check_payload(&self, payload: &[u8]) -> Result<(), V1FrameError> {
    if checksum(payload) != self.checksum {
      return Err(V1FrameError::BadChecksum);
    }
    if !self.command.is_valid_v1() {
      return Err(V1FrameError::InvalidCommand);
    }
    Ok(())
  }

  /// The 16 bytes a V1 peer's first message starts with: the magic and the
  /// `version` command. Core's V2 responder takes a connection opening with
  /// them for V1.
  pub fn version_prefix(magic: Magic) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(magic.as_bytes());
    out[4..].copy_from_slice(CommandString::VERSION.as_bytes());
    out
  }
}

/// The first four bytes of the payload's SHA256d.
pub fn checksum(payload: &[u8]) -> [u8; 4] {
  let hash = sha256d::Hash::hash(payload).to_byte_array();
  [hash[0], hash[1], hash[2], hash[3]]
}

/// Encodes `msg` as a V1 message, header and payload.
///
/// # Errors
///
/// Returns `TooLarge` for a payload above 3 MiB, which Core would not read.
pub fn encode_v1(magic: Magic, msg: &P2pMsg, buf: &mut Vec<u8>) -> Result<(), V1FrameError> {
  let mut payload = Vec::new();
  msg.encode_payload(&mut payload);
  let header = V1Header::for_payload(magic, msg.command(), &payload)?;
  header.to_bytes().encode(buf);
  buf.extend_from_slice(&payload); // nosemgrep: codec-no-raw-extend
  Ok(())
}
