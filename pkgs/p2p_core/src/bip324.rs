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

/// The type byte, a 12-byte command and the 3 MiB message limit.
const MAX_V2_CONTENTS: usize = 1 + 12 + MAX_P2P_PAYLOAD_SIZE;

/// Decodes V2 message contents into a `P2pMsg`.
///
/// The size bound applies to the whole contents and comes before any check
/// of the type, so a short-ID payload may be 12 bytes larger than a V1
/// payload.
///
/// # Errors
///
/// Returns `PayloadTooLarge` above the bound, with an empty command for an
/// unknown short ID. Returns `MissingCommand`, `UnknownShortId` or
/// `InvalidCommand` for a type the transport refuses, and otherwise the error
/// decoding the message.
pub fn decode_v2(contents: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  let mut payload = contents;
  let [short_id] = take(&mut payload).map_err(|_| P2pDecodeError::MissingCommand)?;
  let id = ShortId(short_id);
  let cmd = if id == ShortId::LONG_FORMAT {
    let bytes = take(&mut payload).map_err(|_| P2pDecodeError::MissingCommand)?;
    Some(CommandString::from_bytes(bytes))
  } else if id.is_in_table() {
    Some(id.to_command().unwrap_or(CommandString::from_static("")))
  } else {
    None
  };

  if contents.len() > MAX_V2_CONTENTS {
    return Err(P2pDecodeError::PayloadTooLarge {
      command: cmd.unwrap_or(CommandString::from_static("")),
      size: contents.len(),
      max: MAX_V2_CONTENTS,
    });
  }
  let cmd = cmd.ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
  if id == ShortId::LONG_FORMAT && !cmd.is_valid_v2() {
    return Err(P2pDecodeError::InvalidCommand { command: cmd });
  }
  P2pMsg::decode_unbounded(&cmd, payload)
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::Corpus;
  use hex_conservative::decode_to_vec;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct ContentsVector {
    prefix: String,
    len: usize,
    result: String,
  }

  #[rstest]
  fn decode_v2_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "transport");
    for v in corpus.vectors::<ContentsVector>("v2") {
      let mut contents = decode_to_vec(&v.prefix).unwrap();
      contents.resize(v.len, 0);
      let result = match decode_v2(&contents) {
        Err(P2pDecodeError::PayloadTooLarge { .. }) => "disconnect",
        Err(
          P2pDecodeError::MissingCommand
          | P2pDecodeError::InvalidCommand { .. }
          | P2pDecodeError::UnknownShortId { .. },
        ) => "reject",
        Ok(_)
        | Err(
          P2pDecodeError::UnknownCommand { .. }
          | P2pDecodeError::Consensus(_)
          | P2pDecodeError::PayloadNotEmpty { .. }
          | P2pDecodeError::InvalidValue { .. },
        ) => "accept",
      };
      assert_eq!(result, v.result, "{} of {} bytes", v.prefix, v.len);
    }
  }
}
