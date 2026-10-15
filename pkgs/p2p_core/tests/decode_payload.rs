//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Checks applied by `P2pMsg::decode_payload`.

use dash_p2p_core::{CommandString, P2pDecodeError, P2pMsg};
use dash_types::codec::DecodeError;
use rstest::rstest;

#[rstest]
#[case::short(&[0u8; 7], DecodeError::Eof { needed: 8, remaining: 7 })]
#[case::trailing(&[0u8; 9], DecodeError::TrailingBytes { remaining: 1 })]
fn decode_errors_are_typed(#[case] payload: &[u8], #[case] err: DecodeError) {
  assert_eq!(
    P2pMsg::decode_payload(&CommandString::from_static("ping"), payload),
    Err(P2pDecodeError::Consensus(err))
  );
}

#[rstest]
fn oversized_commands_are_escaped() {
  let cmd = CommandString::from_bytes(*b"pi\nng\0\0\0\0\0\0\0");
  assert_eq!(
    P2pMsg::decode_payload(&cmd, &vec![0; 3 * 1024 * 1024 + 1]).map_err(|e| e.to_string()),
    Err(String::from(
      "payload too large: 3145729 bytes, max 3145728, command pi\\x0ang"
    ))
  );
}
