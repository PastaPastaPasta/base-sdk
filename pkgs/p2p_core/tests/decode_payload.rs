//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Checks that `P2pMsg::decode_payload` and `decode_v2` apply before
//! dispatching a command.

use dash_p2p_core::{CommandString, P2pDecodeError, P2pMsg};
use dash_types::codec::DecodeError;
use rstest::rstest;

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH` (`net.h:84` in v24.0.0-rc.3).
const MAX_MESSAGE: usize = 3 * 1024 * 1024;

/// Core's V1 transport refuses any message above 3 MiB (`net.cpp:737-738`
/// in v24.0.0-rc.3) before it looks at the command, whatever the command is.
#[rstest]
#[case::typed("ping")]
#[case::empty("verack")]
#[case::stub("tx")]
#[case::unknown("nosuchcmd")]
fn every_command_is_bound_by_the_message_limit(#[case] name: &str) {
  let cmd = CommandString::from_static(name);
  let at_max = vec![0u8; MAX_MESSAGE];
  assert!(!matches!(
    P2pMsg::decode_payload(&cmd, &at_max),
    Err(P2pDecodeError::PayloadTooLarge { .. })
  ));
  let above = vec![0u8; MAX_MESSAGE + 1];
  assert_eq!(
    P2pMsg::decode_payload(&cmd, &above),
    Err(P2pDecodeError::PayloadTooLarge {
      command: cmd,
      size: MAX_MESSAGE + 1,
      max: MAX_MESSAGE,
    })
  );
}

fn command(bytes: &[u8]) -> CommandString {
  let mut raw = [0u8; 12];
  raw[..bytes.len()].copy_from_slice(bytes);
  CommandString::from_bytes(raw)
}

/// Core's V1 `IsCommandValid` (`protocol.cpp:232-249` in v24.0.0-rc.3) and
/// V2 `GetMessageType` (`net.cpp:1496-1530`): printable bytes up to the
/// first NUL, then only NULs. V2 also accepts 0x7f.
#[rstest]
#[case::known(b"ping", true, true)]
#[case::full_width(b"abcdefghijkl", true, true)]
#[case::space(b"a b", true, true)]
#[case::empty(b"", true, true)]
#[case::del(b"pi\x7fng", false, true)]
#[case::control(b"pi\x1fng", false, false)]
#[case::high(b"pi\x80ng", false, false)]
#[case::after_nul(b"pi\0ng", false, false)]
fn command_validity_follows_core(#[case] bytes: &[u8], #[case] v1: bool, #[case] v2: bool) {
  let cmd = command(bytes);
  assert_eq!((cmd.is_valid_v1(), cmd.is_valid_v2()), (v1, v2));
}

/// A V2 long-form type that `GetMessageType` refuses is dropped before any
/// handler sees it.
#[rstest]
fn invalid_v2_long_form_type_is_refused() {
  let mut contents = vec![0u8];
  contents.extend_from_slice(command(b"pi\0ng").as_bytes());
  assert_eq!(
    dash_p2p_core::decode_v2(&contents),
    Err(P2pDecodeError::InvalidCommand {
      command: command(b"pi\0ng"),
    })
  );
}

/// A field read past the payload, or bytes left after the message, fail with
/// the decode error itself rather than its text.
#[rstest]
#[case::short(&[0u8; 7], DecodeError::Eof { needed: 8, remaining: 7 })]
#[case::trailing(&[0u8; 9], DecodeError::TrailingBytes { remaining: 1 })]
fn decode_errors_are_typed(#[case] payload: &[u8], #[case] err: DecodeError) {
  assert_eq!(
    P2pMsg::decode_payload(&CommandString::from_static("ping"), payload),
    Err(P2pDecodeError::Consensus(err))
  );
}

/// An empty V2 message has no type byte to read.
#[rstest]
fn empty_v2_message_is_eof() {
  assert_eq!(
    dash_p2p_core::decode_v2(&[]),
    Err(P2pDecodeError::Consensus(DecodeError::Eof {
      needed: 1,
      remaining: 0,
    }))
  );
}

/// Core's V2 transport bounds the whole contents by 1 + 12 + 3 MiB
/// (`net.cpp:1297-1306` in v24.0.0-rc.3) before it reads the type, so a
/// short-ID payload may exceed 3 MiB by 12 bytes.
#[rstest]
fn v2_contents_are_bound_by_core_s_limit() {
  let max_contents = 1 + 12 + MAX_MESSAGE;
  let mut tx = vec![21u8];
  tx.resize(max_contents, 0);
  assert!(!matches!(
    dash_p2p_core::decode_v2(&tx),
    Err(P2pDecodeError::PayloadTooLarge { .. })
  ));
  tx.push(0);
  assert_eq!(
    dash_p2p_core::decode_v2(&tx),
    Err(P2pDecodeError::PayloadTooLarge {
      command: CommandString::from_static("tx"),
      size: max_contents + 1,
      max: max_contents,
    })
  );
}

/// The size check comes first: Core disconnects for an oversized message
/// whose type it would otherwise refuse.
#[rstest]
fn v2_size_is_checked_before_the_type() {
  let max_contents = 1 + 12 + MAX_MESSAGE;
  let mut contents = vec![0u8];
  contents.extend_from_slice(command(b"pi\0ng").as_bytes());
  contents.resize(max_contents + 1, 0);
  assert_eq!(
    dash_p2p_core::decode_v2(&contents),
    Err(P2pDecodeError::PayloadTooLarge {
      command: command(b"pi\0ng"),
      size: max_contents + 1,
      max: max_contents,
    })
  );
}
