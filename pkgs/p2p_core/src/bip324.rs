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

use dash_types::codec::take;

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
  let mut rest = payload;
  let [short_id] = take(&mut rest)?;

  if short_id == 0 {
    // Long format: next 12 bytes are the command string.
    let cmd = CommandString::from_bytes(take(&mut rest)?);
    P2pMsg::decode_payload(&cmd, rest)
  } else {
    // Short ID: resolve to command, then decode payload.
    let sid = ShortId(short_id);
    let cmd = sid
      .to_command()
      .ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
    P2pMsg::decode_payload(&cmd, rest)
  }
}
