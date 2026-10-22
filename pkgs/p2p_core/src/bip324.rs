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
use crate::version::ProtocolVersion;
use crate::P2pDecodeError;

use dash_types::codec::BaseCodec;

/// Encodes a `P2pMsg` into V2 contents, given `common`, the version both
/// peers share.
///
/// The type is the short ID [`P2pMsg::short_id`] gives, else the long format.
/// Until the handshake agrees on a version, pass [`ProtocolVersion::INIT`],
/// which takes the long format for every message.
pub fn encode_v2(msg: &P2pMsg, common: ProtocolVersion, buf: &mut Vec<u8>) {
  match msg.short_id(common) {
    Some(id) => {
      buf.push(id.get());
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

/// The type byte, a 12-byte command and a [`MAX_P2P_PAYLOAD_SIZE`] payload.
const MAX_V2_CONTENTS_SIZE: usize = 1 + 12 + MAX_P2P_PAYLOAD_SIZE;

/// Decodes V2 message contents into a `P2pMsg`.
///
/// The size bound applies to the whole contents and comes before any check
/// of the type. A short-ID payload may thus be 12 bytes larger than a
/// long-format payload.
///
/// # Errors
///
/// Returns `PayloadTooLarge` above the bound, with an empty command for an
/// unknown short ID. Returns `MissingCommand`, `UnknownShortId` or
/// `InvalidCommand` for a type the transport refuses, and otherwise the error
/// decoding the message.
pub fn decode_v2(contents: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  let mut payload = contents;
  let short_id = u8::decode(&mut payload).map_err(|_| P2pDecodeError::MissingCommand)?;
  let id = ShortId::new(short_id);
  let cmd = if id == ShortId::LONG_FORMAT {
    Some(CommandString::decode(&mut payload).map_err(|_| P2pDecodeError::MissingCommand)?)
  } else if id.is_in_table() {
    Some(id.to_command().unwrap_or(CommandString::from_static("")))
  } else {
    None
  };

  if contents.len() > MAX_V2_CONTENTS_SIZE {
    return Err(P2pDecodeError::PayloadTooLarge {
      command: cmd.unwrap_or(CommandString::from_static("")),
      size: contents.len(),
      max: MAX_V2_CONTENTS_SIZE,
    });
  }
  let cmd = cmd.ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
  if id == ShortId::LONG_FORMAT && !cmd.is_valid_v2() {
    return Err(P2pDecodeError::InvalidCommand { command: cmd });
  }
  P2pMsg::decode_unbounded(&cmd, payload)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::Corpus;
  use hex_conservative::decode_to_vec;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SendVector {
    version: i32,
    contents: BTreeMap<String, String>,
  }

  #[rstest]
  fn encode_v2_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "transport");
    for v in corpus.vectors::<SendVector>("v2_send") {
      let version = ProtocolVersion::new(v.version);
      for (name, hex) in &v.contents {
        let cmd = CommandString::from_static(name);
        let contents = decode_to_vec(hex).unwrap();
        let framed = match ShortId::for_send(&cmd, version) {
          Some(id) => vec![id.get()],
          None => [&[0][..], cmd.as_bytes()].concat(),
        };
        assert_eq!(framed, contents, "{name} at {}", v.version);
        // Only messages that take an empty payload can be built without one.
        if let Ok(msg) = P2pMsg::decode_payload(&cmd, &[]) {
          let mut buf = Vec::new();
          encode_v2(&msg, version, &mut buf);
          assert_eq!(buf, contents, "{name} at {}", v.version);
        }
      }
    }
  }
}
