//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP324 V2 message framing.

use crate::codec::MAX_V2_CONTENTS_SIZE;
use crate::command::CommandString;
use crate::ctx::ProtoCtx;
use crate::msg::{DecodedMsg, P2pMsg};
use crate::prelude::*;
use crate::short_id::ShortId;
use crate::version::ProtocolVersion;
use crate::P2pDecodeError;

use dash_types::type_id::Unencodable;

/// Encodes a `P2pMsg` into V2 packet contents for a peer whose common
/// version is `peer_version`, as Core's `V2Transport::SetMessageToSend` does.
///
/// The short ID goes out only from the version [`ShortId::for_send`] gives;
/// otherwise the 13-byte long format, a zero byte and the command.
pub fn encode_v2(msg: &P2pMsg, peer_version: ProtocolVersion, buf: &mut Vec<u8>) {
  let command = msg.command();
  match ShortId::for_send(&command, peer_version) {
    Some(id) => buf.push(id.0),
    None => {
      buf.push(ShortId::LONG_FORMAT.0);
      buf.extend_from_slice(command.as_bytes());
    }
  }
  msg.encode_payload(buf);
}

/// V2 packet contents Core's transport has typed: the type and its payload.
///
/// Only [`split_v2`] builds one, so its payload is within the V2 limit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct V2Message<'a> {
  command: CommandString,
  payload: &'a [u8],
}

impl<'a> V2Message<'a> {
  /// The message type; the empty type for a short ID Core reserves.
  pub const fn command(&self) -> CommandString {
    self.command
  }

  /// The payload after the 1-byte short ID or the 13-byte long-form type.
  pub const fn payload(&self) -> &'a [u8] {
    self.payload
  }

  /// Decodes the payload as Core's handler for the type reads it.
  ///
  /// [`DecodedMsg::consumed`] counts payload bytes.
  ///
  /// # Errors
  ///
  /// Returns `P2pDecodeError` where Core's handler throws, or stops before
  /// reading the rest of the payload.
  pub fn decode(self, ctx: &ProtoCtx) -> Result<DecodedMsg, P2pDecodeError> {
    P2pMsg::dispatch(&self.command, self.payload, ctx)
  }
}

/// Decodes the payload of a V2 message as Core's handler for `cmd` reads it,
/// once the transport has split the contents into type and payload.
///
/// The V2 rules apply, not V1's: the payload may be as long as the contents
/// limit allows after the shortest type that carries `cmd` (a 1-byte short ID
/// if Core's V2 transport maps one to it, else the 13-byte long form), and a
/// long-form type may hold 0x7f.
/// [`split_v2`] already enforces both, so this only matters for a caller that
/// keeps the type and payload apart before decoding.
///
/// # Errors
///
/// Returns `ContentsTooLarge` for a payload no V2 contents can carry, on which
/// Core disconnects, `InvalidCommand` for a type Core's V2 transport refuses,
/// on which it drops the message, or the error of the payload's handler.
pub fn decode_v2_payload(cmd: &CommandString, payload: &[u8], ctx: &ProtoCtx) -> Result<DecodedMsg, P2pDecodeError> {
  let short = *cmd == CommandString::EMPTY || ShortId::from_command(cmd).is_some();
  let size = payload.len().saturating_add(if short { 1 } else { 13 });
  if size > MAX_V2_CONTENTS_SIZE {
    return Err(P2pDecodeError::ContentsTooLarge {
      size,
      max: MAX_V2_CONTENTS_SIZE,
    });
  }
  if !cmd.is_valid_v2() {
    return Err(P2pDecodeError::InvalidCommand { command: *cmd });
  }
  P2pMsg::dispatch(cmd, payload, ctx)
}

/// Splits V2 packet contents into the message type and its payload.
///
/// The contents are bound by Core's V2 limit, checked before the type.
///
/// # Errors
///
/// Returns `ContentsTooLarge` above the limit, on which Core disconnects.
/// Returns `EmptyV2Contents`, `TruncatedV2Type`, `InvalidCommand` or
/// `UnknownShortId` for contents without a message type: drop the message and
/// keep the peer. That includes the short IDs Core reserves without a message,
/// such as 5, which Core types as the empty command and ignores.
pub fn split_v2(contents: &[u8]) -> Result<V2Message<'_>, P2pDecodeError> {
  if contents.len() > MAX_V2_CONTENTS_SIZE {
    return Err(P2pDecodeError::ContentsTooLarge {
      size: contents.len(),
      max: MAX_V2_CONTENTS_SIZE,
    });
  }
  let Some((&short_id, rest)) = contents.split_first() else {
    return Err(P2pDecodeError::EmptyV2Contents);
  };
  if short_id == ShortId::LONG_FORMAT.0 {
    // Long format: next 12 bytes are the command string.
    let Some((bytes, payload)) = rest.split_first_chunk::<12>() else {
      return Err(P2pDecodeError::TruncatedV2Type { remaining: rest.len() });
    };
    let command = CommandString::from_bytes(*bytes);
    if !command.is_valid_v2() {
      return Err(P2pDecodeError::InvalidCommand { command });
    }
    return Ok(V2Message { command, payload });
  }
  let command = match ShortId(short_id).to_command() {
    Some(command) => command,
    None => return Err(P2pDecodeError::UnknownShortId { id: short_id }),
  };
  Ok(V2Message { command, payload: rest })
}

/// Decodes V2 packet contents into a `P2pMsg` under `ctx`.
///
/// [`split_v2`], then [`V2Message::decode`]. A policy that needs the type of
/// a payload its handler rejects calls the two itself.
///
/// # Errors
///
/// Returns the error of [`split_v2`] or of the payload's handler.
pub fn decode_v2(contents: &[u8], ctx: &ProtoCtx) -> Result<DecodedMsg, P2pDecodeError> {
  split_v2(contents)?.decode(ctx)
}
