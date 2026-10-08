//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Payloads Dash Core accepts or rejects, decoded under Core's handler policy.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, DecodedMsg, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use rstest::rstest;

#[derive(::serde::Deserialize)]
struct MsgVector {
  name: String,
  command: String,
  version: Option<i32>,
  raw: String,
  core: String,
}

fn corpus() -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "decode_domain")
}

fn ctx(version: i32) -> ProtoCtx {
  ProtoCtx::new(ProtocolVersion::new(version), BlsCtx::BASIC)
}

fn command(name: &str) -> CommandString {
  let mut bytes = [0u8; 12];
  bytes[..name.len()].copy_from_slice(name.as_bytes());
  CommandString::from_bytes(bytes)
}

fn decode(v: &MsgVector) -> Result<DecodedMsg, P2pDecodeError> {
  let raw = vec_from_hex(&v.raw);
  P2pMsg::decode_with_policy(&command(&v.command), &raw, &ctx(v.version.unwrap_or(70240)))
}

#[rstest]
fn headers_limits_follow_core() {
  for v in corpus().vectors::<MsgVector>("headers") {
    let decoded = decode(&v);
    match v.core.as_str() {
      "accept" => {
        let msg = decoded.unwrap_or_else(|e| panic!("{}: {e}", v.name)).msg;
        assert!(
          matches!(msg, P2pMsg::Headers(ref h) if h.headers.len() == 1),
          "{}: {msg:?}",
          v.name
        );
      }
      "throw" => assert!(
        matches!(decoded, Err(P2pDecodeError::Consensus(_))),
        "{}: {decoded:?}",
        v.name
      ),
      "misbehaving 20" => {
        assert!(
          matches!(decoded, Err(P2pDecodeError::TooManyEntries { .. })),
          "{}: {decoded:?}",
          v.name
        )
      }
      other => panic!("{}: unexpected outcome {other}", v.name),
    }
  }
}

#[rstest]
fn ignored_payloads_decode() {
  for v in corpus().vectors::<MsgVector>("ignored_payload") {
    let decoded = decode(&v).unwrap_or_else(|e| panic!("{}: {e}", v.name));
    match decoded.msg {
      P2pMsg::Unknown { command, payload } => {
        assert_eq!(command.as_str(), v.command);
        assert_eq!(payload, vec_from_hex(&v.raw));
      }
      P2pMsg::Verack | P2pMsg::SendHeaders2 => assert_eq!(decoded.consumed, 0, "{}", v.name),
      other => panic!("{}: {other:?}", v.name),
    }
  }
}

#[rstest]
fn senddsq_carries_its_payload() {
  for v in corpus().vectors::<MsgVector>("senddsq") {
    let decoded = decode(&v).unwrap();
    assert_eq!(decoded.msg, P2pMsg::SendDsq(vec_from_hex(&v.raw)), "{}", v.name);
  }
}

/// A command string with no handler keeps its raw payload on re-encode.
#[rstest]
fn unknown_command_round_trips() {
  let cmd = command("bs4aprobe");
  let decoded = P2pMsg::decode_with_policy(&cmd, &[0, 1, 2], &ctx(70240)).unwrap();
  assert_eq!(decoded.consumed, 3);
  assert_eq!(decoded.msg.command(), cmd);
  assert!(decoded.msg.short_id().is_none());
  let mut buf = Vec::new();
  decoded.msg.encode_payload(&mut buf);
  assert_eq!(buf, [0, 1, 2]);
}
