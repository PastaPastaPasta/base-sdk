//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP324 V2 message framing.

use crate::command::CommandString;
use crate::msg::P2pMsg;
use crate::prelude::*;
use crate::short_id::ShortId;
use crate::P2pDecodeError;

use dash_types::codec::DecodeError;

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

/// Decodes V2 framed bytes into a `P2pMsg`.
pub fn decode_v2(payload: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  if payload.is_empty() {
    return Err(
      DecodeError::Eof {
        needed: 1,
        remaining: 0,
      }
      .into(),
    );
  }

  let short_id = payload[0];
  let rest = &payload[1..];

  if short_id == 0 {
    // Long format: next 12 bytes are the command string.
    if rest.len() < 12 {
      return Err(
        DecodeError::Eof {
          needed: 12,
          remaining: rest.len(),
        }
        .into(),
      );
    }
    let mut cmd_bytes = [0u8; 12];
    cmd_bytes.copy_from_slice(&rest[..12]);
    let cmd = CommandString::from_bytes(cmd_bytes);
    if !cmd.is_valid_v2() {
      return Err(P2pDecodeError::InvalidCommand { command: cmd });
    }
    P2pMsg::decode_payload(&cmd, &rest[12..])
  } else {
    // Short ID: resolve to command, then decode payload.
    let sid = ShortId(short_id);
    let cmd = sid
      .to_command()
      .ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
    P2pMsg::decode_payload(&cmd, rest)
  }
}
