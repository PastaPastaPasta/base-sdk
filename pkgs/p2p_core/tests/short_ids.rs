//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The V2 short-ID tables and send gate against Dash Core's.

#![cfg(feature = "serde")]
#![expect(clippy::unwrap_used, reason = "test code")]

use std::collections::BTreeMap;

use dash_dev::Corpus;
use dash_p2p_core::{encode_v2, split_v2, CommandString, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion, ShortId};
use dash_pkc::bls::BlsCtx;
use rstest::rstest;

#[derive(Clone, Copy, ::serde::Deserialize)]
struct Slot {
  id: u8,
  min_version: i32,
}

fn corpus() -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "short_ids")
}

fn command(name: &str) -> CommandString {
  let mut bytes = [0u8; 12];
  bytes[..name.len()].copy_from_slice(name.as_bytes());
  CommandString::from_bytes(bytes)
}

/// Versions around every boundary the gate has.
const VERSIONS: [i32; 7] = [209, 70221, 70234, 70235, 70239, 70240, 70242];

#[rstest]
fn the_send_gate_is_cores() {
  let send: BTreeMap<String, Option<Slot>> = corpus().value("send");
  assert_eq!(send.len(), 75, "74 commands and the empty type");
  for (name, slot) in &send {
    for v in VERSIONS {
      let want = slot.filter(|s| v >= s.min_version).map(|s| ShortId(s.id));
      assert_eq!(
        ShortId::for_send(&command(name), ProtocolVersion::new(v)),
        want,
        "{name:?} at {v}"
      );
    }
  }
}

#[rstest]
fn before_the_version_every_message_is_long_form() {
  let init: i32 = corpus().value("init_version");
  assert_eq!(ProtocolVersion::INIT, ProtocolVersion::new(init));
  let send: BTreeMap<String, Option<Slot>> = corpus().value("send");
  for name in send.keys() {
    assert_eq!(
      ShortId::for_send(&command(name), ProtocolVersion::INIT),
      None,
      "{name:?}"
    );
  }
}

#[rstest]
fn encode_v2_follows_the_gate() {
  let msg = P2pMsg::Ping(dash_p2p_core::Ping { nonce: 7 });
  let mut long = Vec::new();
  encode_v2(&msg, ProtocolVersion::new(70234), &mut long);
  assert_eq!(&long[..13], b"\0ping\0\0\0\0\0\0\0\0");
  let mut short = Vec::new();
  encode_v2(&msg, ProtocolVersion::BIP324_BASELINE, &mut short);
  assert_eq!(short[0], 18);
  assert_eq!(&short[1..], &long[13..]);
}

#[rstest]
fn every_core_command_is_known() {
  let send: BTreeMap<String, Option<Slot>> = corpus().value("send");
  let ctx = ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC);
  for name in send.keys().filter(|n| !n.is_empty()) {
    // An empty payload: decoders may fail, but never as an unknown command.
    if let Ok(d) = P2pMsg::decode_with_policy(&command(name), &[], &ctx) {
      assert!(!d.msg.is_unknown(), "{name}");
      assert_eq!(d.msg.command(), command(name));
    }
    let slot = ShortId::from_command(&command(name));
    assert_eq!(slot, send[name].map(|s| ShortId(s.id)), "{name}");
  }
}

#[rstest]
fn the_receive_table_is_cores() {
  let recv: BTreeMap<String, Option<String>> = corpus().value("recv");
  assert_eq!(recv.len(), 256);
  for (byte, want) in &recv {
    let b: u8 = byte.parse().unwrap();
    let mut contents = vec![b];
    contents.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    contents.extend_from_slice(&7u64.to_le_bytes());
    let got = split_v2(&contents);
    match want.as_deref() {
      Some("long") => assert_eq!(got.unwrap().command(), CommandString::PING, "{b}"),
      Some(name) => assert_eq!(got.unwrap().command(), command(name), "{b}"),
      None => assert_eq!(got, Err(P2pDecodeError::UnknownShortId { id: b }), "{b}"),
    }
  }
}
