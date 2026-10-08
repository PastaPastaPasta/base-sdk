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

/// Decodes V2 packet contents into a `P2pMsg` under `ctx`.
///
/// [`DecodedMsg::consumed`] counts payload bytes after the 1-byte short ID or
/// the 13-byte long-form type. The contents are bound by Core's V2 limit,
/// checked before the type, and the V1 payload limit does not apply.
///
/// # Errors
///
/// Returns `ContentsTooLarge` above the limit, on which Core disconnects.
/// Returns another `P2pDecodeError` for empty contents, a cut long-form type
/// or an unassigned short ID, which Core drops, or for a payload
/// [`P2pMsg::decode_with_policy`] rejects.
pub fn decode_v2(contents: &[u8], ctx: &ProtoCtx) -> Result<DecodedMsg, P2pDecodeError> {
  if contents.len() > MAX_V2_CONTENTS_SIZE {
    return Err(P2pDecodeError::ContentsTooLarge {
      size: contents.len(),
      max: MAX_V2_CONTENTS_SIZE,
    });
  }
  let Some((&short_id, rest)) = contents.split_first() else {
    return Err(P2pDecodeError::Consensus(String::from(
      "unexpected eof: needed 1 byte, 0 remaining",
    )));
  };

  if short_id == 0 {
    // Long format: next 12 bytes are the command string.
    let Some((cmd_bytes, payload)) = rest.split_first_chunk::<12>() else {
      return Err(P2pDecodeError::Consensus(format!(
        "unexpected eof: needed 12 bytes, {} remaining",
        rest.len()
      )));
    };
    let cmd = CommandString::from_bytes(*cmd_bytes);
    P2pMsg::dispatch(&cmd, payload, ctx)
  } else {
    // Short ID: resolve to command, then decode payload.
    let cmd = ShortId(short_id)
      .to_command()
      .ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
    P2pMsg::dispatch(&cmd, rest, ctx)
  }
}
