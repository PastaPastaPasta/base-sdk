//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 transport outcomes of `decode_v2` against the reference vectors.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::Corpus;
use dash_p2p_core::{decode_v2, P2pDecodeError};
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
