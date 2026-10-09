//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Where Core's own reader stops, and why, against base-sdk's.

#![cfg(feature = "serde")]
#![expect(clippy::panic, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, GetBlockTxn, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::MAX_SER_SIZE;
use rstest::rstest;

#[derive(::serde::Deserialize)]
struct Case {
  payload: String,
  consumed: usize,
  error: String,
}

/// Whether base-sdk's error is the one Core threw.
fn same_class(core: &str, ours: &DecodeError) -> bool {
  match ours {
    DecodeError::Eof { .. } => core.contains("end of data"),
    DecodeError::NonMinimalCompactSize { .. } => core.contains("non-canonical ReadCompactSize()"),
    DecodeError::CompactSizeExceedsLimit { limit, .. } if *limit == MAX_SER_SIZE => {
      core.contains("ReadCompactSize(): size too large")
    }
    DecodeError::CompactSizeExceedsLimit { limit, .. } if *limit == usize::from(u16::MAX) => {
      core.contains("differential value overflow")
    }
    _ => false,
  }
}

#[rstest]
fn getblocktxn_stops_where_core_does() {
  let cases: Vec<Case> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_cursors").value("getblocktxn");
  assert!(cases.len() > 400);
  let ctx = ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC);
  for c in &cases {
    let payload = vec_from_hex(&c.payload);
    let mut cursor = &payload[..];
    let r = GetBlockTxn::decode(&mut cursor);
    let consumed = payload.len() - cursor.len();
    assert_eq!(consumed, c.consumed, "{}: bytes read", c.payload);
    match (&r, c.error.is_empty()) {
      (Ok(_), true) => {}
      (Err(e), false) => assert!(same_class(&c.error, e), "{}: {e} vs {}", c.payload, c.error),
      _ => panic!("{}: {r:?} vs {:?}", c.payload, c.error),
    }
    // The handler path reads the same and fails the same way.
    match P2pMsg::decode_with_policy(&CommandString::GETBLOCKTXN, &payload, &ctx) {
      Ok(d) => assert_eq!(d.consumed, c.consumed, "{}", c.payload),
      Err(P2pDecodeError::Consensus(e)) => assert!(same_class(&c.error, &e), "{}", c.payload),
      Err(e) => panic!("{}: {e}", c.payload),
    }
  }
}
