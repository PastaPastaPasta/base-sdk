//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Payloads Dash Core accepts or rejects, decoded under Core's handler policy.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, DecodedMsg, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion, Version};
use dash_pkc::bls::BlsCtx;
use dash_types::codec::BaseCodec;
use rstest::rstest;

#[derive(::serde::Deserialize)]
struct VersionVector {
  name: String,
  raw: String,
  core: String,
  relaytxes: Option<bool>,
  groups: Option<usize>,
}

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

/// Counts the optional `version` field groups present after `addr_recv`.
fn groups(v: &Version) -> usize {
  [
    v.addr_send.is_some() && v.nonce.is_some(),
    v.user_agent.is_some(),
    v.start_height.is_some(),
    v.relay.is_some(),
    v.mnauth_challenge.is_some(),
    v.mn_connection.is_some(),
  ]
  .iter()
  .take_while(|present| **present)
  .count()
}

#[rstest]
fn version_reads_optional_fields_as_core() {
  for v in corpus().vectors::<VersionVector>("version") {
    let raw = vec_from_hex(&v.raw);
    let decoded = P2pMsg::decode_with_policy(&CommandString::VERSION, &raw, &ctx(209));
    if v.core == "throw" {
      assert!(
        matches!(decoded, Err(P2pDecodeError::Consensus(_))),
        "{}: {decoded:?}",
        v.name
      );
      continue;
    }
    let DecodedMsg {
      msg: P2pMsg::Version(version),
      consumed,
    } = decoded.unwrap()
    else {
      panic!("{}: not a version", v.name);
    };
    if let Some(expected) = v.groups {
      assert_eq!(groups(&version), expected, "{}", v.name);
      // An absent relay field defaults to true in Core.
      let relay = version.relay.is_none_or(|r| r.get());
      assert_eq!(Some(relay), v.relaytxes, "{}", v.name);
    }
    match v.core.as_str() {
      "disconnect: inbound masternode" => assert_eq!(version.mn_connection.map(|b| b.get()), Some(true)),
      "disconnect: obsolete version" => assert!(version.protocol_version < ProtocolVersion::MIN_PEER),
      _ => {}
    }
    // Core ignores bytes after fMasternode; re-encoding writes the fields read.
    let mut buf = Vec::new();
    version.encode(&mut buf);
    assert_eq!(buf.len(), consumed, "{}", v.name);
    if v.name != "relay_02" && v.name != "relay_ff" && v.name != "mn_02" {
      assert_eq!(buf, raw[..consumed], "{}", v.name);
    }
  }
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
