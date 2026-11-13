//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Round-trip checks for Dash Core's captured P2P messages.

#![cfg(feature = "serde")]
#![expect(clippy::panic, reason = "test code")]

use ::serde::de::IgnoredAny;
use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use rstest::rstest;

use std::collections::{BTreeMap, BTreeSet};

#[derive(::serde::Deserialize)]
struct Key {
  network: String,
  dir: String,
  command: String,
  version: i32,
}

impl Key {
  fn label(&self) -> String {
    format!("{}/{}/{}/{}", self.network, self.dir, self.command, self.version)
  }

  fn command(&self) -> CommandString {
    let raw = self.command.as_bytes();
    assert!(raw.len() <= 12, "{}: command length", self.label());
    let mut bytes = [0; 12];
    bytes[..raw.len()].copy_from_slice(raw);
    let command = CommandString::from_bytes(bytes);
    assert!(command.is_valid_v1(), "{}: invalid command", self.label());
    assert_eq!(command.as_str(), self.command, "{}: command padding", self.label());
    command
  }

  fn ctx(&self) -> ProtoCtx {
    ProtoCtx::new(ProtocolVersion::new(self.version), BlsCtx::BASIC)
  }
}

#[derive(::serde::Deserialize)]
struct Message {
  #[serde(flatten)]
  key: Key,
  raw: String,
}

#[derive(::serde::Deserialize)]
struct Seen {
  #[serde(flatten)]
  key: Key,
  count: u64,
}

/// The commands Core knows: `allNetMessageTypes`, from `short_ids`.
fn core_commands() -> BTreeSet<String> {
  let send: BTreeMap<String, IgnoredAny> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "short_ids").value("send");
  send.into_keys().filter(|name| !name.is_empty()).collect()
}

#[rstest]
fn core_captures_round_trip() {
  let known = core_commands();
  let messages = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_captures").vectors::<Message>("messages");
  for message in messages {
    let key = &message.key;
    let label = key.label();
    let command = key.command();
    let payload = vec_from_hex(&message.raw);
    let decoded =
      P2pMsg::decode_with_policy(&command, &payload, &key.ctx()).unwrap_or_else(|e| panic!("{label}: decode: {e}"));
    assert_eq!(
      decoded.msg.is_unknown(),
      !known.contains(&key.command),
      "{label}: unknown"
    );
    assert!(!decoded.msg.is_stub(), "{label}: stub message");
    assert_eq!(decoded.msg.command(), command, "{label}: command");
    assert_eq!(decoded.consumed, payload.len(), "{label}: consumed");
    let mut encoded = Vec::new();
    decoded.msg.encode_payload(&mut encoded);
    assert_eq!(encoded, payload, "{label}: payload round-trip");
  }
}

#[rstest]
fn core_captures_seen_commands_dispatch_as_core() {
  let known = core_commands();
  let seen = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_captures").vectors::<Seen>("seen");
  for row in seen {
    let label = row.key.label();
    assert!(row.count > 0, "{label}: empty count");
    let typed = known.contains(&row.key.command);
    match P2pMsg::decode_with_policy(&row.key.command(), &[], &row.key.ctx()) {
      Ok(decoded) => assert_eq!(decoded.msg.is_unknown(), !typed, "{label}: unknown"),
      Err(e) => assert!(typed, "{label}: decode: {e}"),
    }
  }
}
