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
  core: String,
  consumed: Option<usize>,
}

/// Core's verdict, and on success the bytes it read. Where a failed read
/// stops and its error are not compared: no Core logic observes them.
#[rstest]
fn getblocktxn_verdicts_are_cores() {
  let cases: Vec<Case> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_getblocktxn").value("getblocktxn");
  assert!(cases.len() > 400);
  assert!(cases.iter().any(|c| c.core == "read") && cases.iter().any(|c| c.core == "reject"));
  let ctx = ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC);
  for c in &cases {
    let payload = vec_from_hex(&c.payload);
    let mut cursor = &payload[..];
    let r = GetBlockTxn::decode(&mut cursor);
    let read = match c.core.as_str() {
      "read" => c.consumed,
      "reject" => None,
      other => panic!("{}: verdict {other}", c.payload),
    };
    match (&r, read) {
      (Ok(_), Some(n)) => assert_eq!(payload.len() - cursor.len(), n, "{}: bytes read", c.payload),
      (Err(_), None) => {}
      _ => panic!("{}: {r:?}, Core {}", c.payload, c.core),
    }
    // The handler path gives the same verdict.
    match P2pMsg::decode_with_policy(&CommandString::GETBLOCKTXN, &payload, &ctx) {
      Ok(d) => assert_eq!(Some(d.consumed), read, "{}", c.payload),
      Err(P2pDecodeError::Consensus(_)) => assert!(read.is_none(), "{}", c.payload),
      Err(e) => panic!("{}: {e}", c.payload),
    }
  }
}
