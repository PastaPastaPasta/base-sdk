//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP324 V2 message framing.

use crate::codec::MAX_P2P_PAYLOAD_SIZE;
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

/// Core's `V2Transport::MAX_CONTENTS_LEN`: the type byte, a 12-byte command
/// and the 3 MiB message limit (`net.cpp:1297-1299` in v24.0.0-rc.3).
const MAX_V2_CONTENTS: usize = 1 + 12 + MAX_P2P_PAYLOAD_SIZE;

/// Decodes V2 message contents into a `P2pMsg`.
///
/// Core bounds the whole contents before it reads the type, so a short-ID
/// message may carry up to 12 bytes more payload than a V1 message. An
/// oversized message with an unknown short ID reports an empty command.
pub fn decode_v2(contents: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  let Some((&short_id, rest)) = contents.split_first() else {
    return Err(
      DecodeError::Eof {
        needed: 1,
        remaining: 0,
      }
      .into(),
    );
  };

  let (cmd, payload) = if short_id == 0 {
    // Long format: next 12 bytes are the command string.
    let Some((cmd_bytes, payload)) = rest.split_first_chunk::<12>() else {
      return Err(
        DecodeError::Eof {
          needed: 12,
          remaining: rest.len(),
        }
        .into(),
      );
    };
    (Some(CommandString::from_bytes(*cmd_bytes)), payload)
  } else {
    (ShortId(short_id).to_command(), rest)
  };

  if contents.len() > MAX_V2_CONTENTS {
    return Err(P2pDecodeError::PayloadTooLarge {
      command: cmd.unwrap_or(CommandString::from_bytes([0; 12])),
      size: contents.len(),
      max: MAX_V2_CONTENTS,
    });
  }
  let cmd = cmd.ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
  if short_id == 0 && !cmd.is_valid_v2() {
    return Err(P2pDecodeError::InvalidCommand { command: cmd });
  }
  P2pMsg::decode_unbounded(&cmd, payload)
}
