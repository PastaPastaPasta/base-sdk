//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 transport outcomes of `split_v2` and `decode_v2` against the reference
//! vectors.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::Corpus;
use dash_p2p_core::{decode_v2, split_v2, CommandString, P2pDecodeError};
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
        P2pDecodeError::MissingCommand | P2pDecodeError::InvalidCommand { .. } | P2pDecodeError::UnknownShortId { .. },
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

#[rstest]
#[case::long(b"\0ping\0\0\0\0\0\0\0\0\x07\x07", CommandString::PING, 2)]
#[case::long_del(b"\0pi\x7fng\0\0\0\0\0\0\0\x07", CommandString::from_static("pi\x7fng"), 1)]
#[case::long_empty(b"\0\0\0\0\0\0\0\0\0\0\0\0\0", CommandString::EMPTY, 0)]
#[case::short(b"\x12\x07\x07\x07\x07\x07\x07\x07\x07", CommandString::PING, 8)]
#[case::dash_short(b"\xa8\x07", CommandString::PLATFORMBAN, 1)]
#[case::unassigned(b"\x05\x07\x07", CommandString::EMPTY, 2)]
#[case::unimplemented(b"\x20", CommandString::EMPTY, 0)]
fn split_v2_types_the_contents(#[case] contents: &[u8], #[case] command: CommandString, #[case] size: usize) {
  let msg = split_v2(contents).unwrap();
  assert_eq!(msg.command(), command);
  assert_eq!(msg.payload(), &contents[contents.len() - size..]);
}

#[rstest]
#[case::unassigned(&[5])]
#[case::long_empty(&[0; 13])]
fn the_empty_type_has_no_message(#[case] contents: &[u8]) {
  assert_eq!(
    split_v2(contents).unwrap().decode(),
    Err(P2pDecodeError::UnknownCommand { bytes: [0; 12] })
  );
}

#[rstest]
#[case::empty(&[], P2pDecodeError::MissingCommand)]
#[case::cut_long(b"\0ping\0\0\0\0\0\0\0", P2pDecodeError::MissingCommand)]
#[case::past_bip324(&[33], P2pDecodeError::UnknownShortId { id: 33 })]
#[case::past_dash(&[169], P2pDecodeError::UnknownShortId { id: 169 })]
#[case::control(
  b"\0pi\x1fng\0\0\0\0\0\0\0",
  P2pDecodeError::InvalidCommand { command: CommandString::from_bytes(*b"pi\x1fng\0\0\0\0\0\0\0") }
)]
fn split_v2_refuses_untyped_contents(#[case] contents: &[u8], #[case] err: P2pDecodeError) {
  assert_eq!(split_v2(contents), Err(err));
}
