//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Checks `P2pMsg::decode_payload` applies before dispatching a command.

use dash_p2p_core::{CommandString, P2pDecodeError, P2pMsg};
use rstest::rstest;

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH` (`net.h:84` in v24.0.0-rc.3).
const MAX_MESSAGE: usize = 3 * 1024 * 1024;

/// Core's transport refuses any message above 3 MiB (`net.cpp:737-738` in
/// v24.0.0-rc.3) before it looks at the command, whatever the command is.
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
