//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's own `getblocktxn` reader, against base-sdk's.

#![cfg(feature = "serde")]
#![expect(clippy::panic, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, GetBlockTxn, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use dash_types::codec::BaseCodec;
use rstest::rstest;

#[derive(::serde::Deserialize)]
struct Case {
  payload: String,
  consumed: usize,
  error: String,
}

/// Core's verdict, and on success the bytes it read. Where a failed read
/// stops and its error class are not compared: no Core logic observes them
/// (DEC-98).
#[rstest]
fn getblocktxn_verdicts_are_cores() {
  let cases: Vec<Case> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_cursors").value("getblocktxn");
  assert!(cases.len() > 400);
  let ctx = ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC);
  for c in &cases {
    let payload = vec_from_hex(&c.payload);
    let mut cursor = &payload[..];
    let r = GetBlockTxn::decode(&mut cursor);
    match (&r, c.error.is_empty()) {
      (Ok(_), true) => assert_eq!(payload.len() - cursor.len(), c.consumed, "{}: bytes read", c.payload),
      (Err(_), false) => {}
      _ => panic!("{}: {r:?} vs {:?}", c.payload, c.error),
    }
    // The handler path gives the same verdict.
    match P2pMsg::decode_with_policy(&CommandString::GETBLOCKTXN, &payload, &ctx) {
      Ok(d) => assert_eq!(d.consumed, c.consumed, "{}", c.payload),
      Err(P2pDecodeError::Consensus(_)) => assert!(!c.error.is_empty(), "{}", c.payload),
      Err(e) => panic!("{}: {e}", c.payload),
    }
  }
}
