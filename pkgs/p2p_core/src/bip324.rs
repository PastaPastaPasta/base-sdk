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

/// Splits V2 packet contents into the message type and its payload.
///
/// The contents are bound by Core's V2 limit, checked before the type. A
/// short ID Core reserves without a message, such as 5, gives the empty
/// type, which Core's handlers treat as an unknown command.
///
/// # Errors
///
/// Returns `ContentsTooLarge` above the limit, on which Core disconnects.
/// Returns `EmptyV2Contents`, `TruncatedV2Type` or `UnknownShortId` for
/// contents Core cannot type, which it drops while keeping the peer.
pub fn split_v2(contents: &[u8]) -> Result<(CommandString, &[u8]), P2pDecodeError> {
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
    return match rest.split_first_chunk::<12>() {
      Some((cmd, payload)) => Ok((CommandString::from_bytes(*cmd), payload)),
      None => Err(P2pDecodeError::TruncatedV2Type { remaining: rest.len() }),
    };
  }
  match ShortId(short_id).to_command() {
    Some(cmd) => Ok((cmd, rest)),
    None if is_core_short_id(short_id) => Ok((CommandString::from_bytes([0; 12]), rest)),
    None => Err(P2pDecodeError::UnknownShortId { id: short_id }),
  }
}

/// Decodes V2 packet contents into a `P2pMsg` under `ctx`.
///
/// [`split_v2`], then [`P2pMsg::decode_v2_payload`]. [`DecodedMsg::consumed`]
/// counts payload bytes after the type. A policy that needs the command of a
/// payload its handler rejects calls the two itself.
///
/// # Errors
///
/// Returns the error of [`split_v2`] or of the payload's handler.
pub fn decode_v2(contents: &[u8], ctx: &ProtoCtx) -> Result<DecodedMsg, P2pDecodeError> {
  let (cmd, payload) = split_v2(contents)?;
  P2pMsg::decode_v2_payload(&cmd, payload, ctx)
}
