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
use crate::P2pDecodeError;

use dash_types::type_id::Unencodable;

/// Encodes a `P2pMsg` into V2 framed bytes.
pub fn encode_v2(msg: &P2pMsg, buf: &mut Vec<u8>) {
  match msg.short_id() {
    Some(id) => {
      buf.push(id.0);
    }
    None => {
      // Long format: ID 0 + 12-byte command string.
      buf.push(0);
      let cmd = msg.command();
      buf.extend_from_slice(cmd.as_bytes());
    }
  }
  msg.encode_payload(buf);
}

/// Whether Core gives the short ID a slot: Bitcoin's 1 to 32, Dash's 128 to
/// 168 (`IsValidV2ShortID`). A slot without a message has the empty type.
const fn is_core_short_id(id: u8) -> bool {
  matches!(id, 1..=32 | 128..=168)
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

/// Splits V2 packet contents into the message type and its payload.
///
/// The contents are bound by Core's V2 limit, checked before the type. A
/// short ID Core reserves without a message, such as 5, gives the empty
/// type, which Core's handlers treat as an unknown command.
///
/// # Errors
///
/// Returns `ContentsTooLarge` above the limit, on which Core disconnects.
/// Returns `EmptyV2Contents`, `TruncatedV2Type`, `InvalidCommand` or
/// `UnknownShortId` for contents Core cannot type, which it drops while
/// keeping the peer.
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
  if short_id == 0 {
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
    None if is_core_short_id(short_id) => CommandString::from_bytes([0; 12]),
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
