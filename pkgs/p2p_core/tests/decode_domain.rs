//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Payloads Dash Core accepts or rejects, decoded under Core's handler policy.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{
  decode_v2, split_v2, CommandString, DecodedMsg, Headers, Headers2, P2pDecodeError, P2pMsg, Ping, Pong, ProtoCtx,
  ProtocolVersion, QSendRecSigs, SendDsq, Version,
};
use dash_pkc::bls::BlsCtx;
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::CoreBool;
use rstest::rstest;

#[derive(::serde::Deserialize)]
struct VersionVector {
  name: String,
  raw: String,
  core: String,
  subver: Option<String>,
  startingheight: Option<i32>,
  relaytxes: Option<bool>,
  groups: Option<usize>,
}

#[derive(::serde::Deserialize)]
struct PongVector {
  name: String,
  raw: String,
  core: String,
}

#[derive(::serde::Deserialize)]
struct V2Vector {
  form: String,
  payload_len: usize,
  contents_len: usize,
  core: String,
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

/// Bytes of the `version` fields Core reads unconditionally, to `addr_recv`.
const VERSION_HEAD_LEN: usize = 46;

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
    match v.core.as_str() {
      // Core throws. Past `addr_recv` it has already checked the head, which
      // the error keeps; inside the head there is nothing to check.
      "throw" if raw.len() > VERSION_HEAD_LEN => assert!(
        matches!(decoded, Err(P2pDecodeError::VersionTail { .. })),
        "{}: {decoded:?}",
        v.name
      ),
      "throw" => assert!(
        matches!(decoded, Err(P2pDecodeError::Consensus(_))),
        "{}: {decoded:?}",
        v.name
      ),
      // Core disconnects on the version alone, whatever follows it.
      "disconnect: obsolete version" => {
        let head = match decoded {
          Ok(DecodedMsg {
            msg: P2pMsg::Version(version),
            ..
          }) => version,
          Err(P2pDecodeError::VersionTail { head, .. }) => *head,
          other => panic!("{}: {other:?}", v.name),
        };
        assert!(head.protocol_version < ProtocolVersion::MIN_PEER, "{}", v.name);
      }
      core => {
        let DecodedMsg {
          msg: P2pMsg::Version(version),
          consumed,
        } = decoded.unwrap()
        else {
          panic!("{}: not a version", v.name);
        };
        if core == "disconnect: inbound masternode" {
          assert_eq!(version.mn_connection.map(|b| b.get()), Some(true), "{}", v.name);
        }
        if let Some(expected) = v.groups {
          assert_eq!(groups(&version), expected, "{}", v.name);
          // Core's defaults for absent fields: no subver, height -1, relay.
          let relay = version.relay.is_none_or(|r| r.get());
          assert_eq!(Some(relay), v.relaytxes, "{}", v.name);
          let subver = version.user_agent.as_ref().and_then(|u| u.as_str()).unwrap_or_default();
          assert_eq!(Some(subver), v.subver.as_deref(), "{}", v.name);
          assert_eq!(Some(version.start_height.unwrap_or(-1)), v.startingheight, "{}", v.name);
        }
        // Core ignores bytes after fMasternode; re-encoding writes the fields read.
        let mut buf = Vec::new();
        version.encode(&mut buf);
        assert_eq!(buf.len(), consumed, "{}", v.name);
        if !matches!(v.name.as_str(), "relay_02" | "relay_ff" | "mn_02") {
          assert_eq!(buf, raw[..consumed], "{}", v.name);
        }
      }
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

/// Core reads one `bool` from each, any non-zero byte being true.
#[rstest]
fn control_messages_read_a_core_bool() {
  for v in corpus().vectors::<MsgVector>("control") {
    let raw = vec_from_hex(&v.raw);
    let decoded = decode(&v);
    if v.core == "throw" {
      assert!(
        matches!(decoded, Err(P2pDecodeError::Consensus(_))),
        "{}: {decoded:?}",
        v.name
      );
      continue;
    }
    let flag = CoreBool(raw[0] != 0);
    let expected = match v.command.as_str() {
      "senddsq" => P2pMsg::SendDsq(SendDsq { send_dsq: flag }),
      _ => P2pMsg::QSendRecSigs(QSendRecSigs { send_rec_sigs: flag }),
    };
    assert_eq!(decoded.map(|d| d.msg), Ok(expected), "{}", v.name);
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

/// Core's V1 transport refuses a payload above `MAX_PROTOCOL_MESSAGE_LENGTH`
/// (3 MiB, `net.h` and `net.cpp` `readHeader` at both pins) before it reads
/// the command. The bound is from source; the r1 review saw both pins
/// disconnect at 3 MiB + 1 for every command.
#[rstest]
#[case::typed("ping")]
#[case::empty("verack")]
#[case::stub("tx")]
#[case::unknown("bs4aprobe")]
fn every_command_is_bound_by_the_protocol_limit(#[case] name: &str) {
  let at_max = vec![0u8; 3 * 1024 * 1024];
  assert!(!matches!(
    P2pMsg::decode_with_policy(&command(name), &at_max, &ctx(70240)),
    Err(P2pDecodeError::PayloadTooLarge { .. })
  ));
  let above = vec![0u8; 3 * 1024 * 1024 + 1];
  assert!(matches!(
    P2pMsg::decode_with_policy(&command(name), &above, &ctx(70240)),
    Err(P2pDecodeError::PayloadTooLarge { .. })
  ));
}

/// Core's V2 transport bounds the whole contents, type included, before it
/// reads the type, so a short-ID payload may exceed the V1 limit by 12 bytes.
#[rstest]
fn v2_contents_are_bound_as_core() {
  const NONCE: u64 = 0x0124_5678;
  let commands = v1_commands();
  for v in corpus().vectors::<V2Vector>("v2_contents") {
    let long_form = v.form.strip_prefix("long_").map(|name| commands[name]);
    let mut contents = match (v.form.as_str(), long_form) {
      (_, Some(command)) => [&[0][..], command.as_bytes()].concat(),
      ("short", _) => vec![18],
      ("long", _) => b"\0ping\0\0\0\0\0\0\0\0".to_vec(),
      ("unassigned", _) => vec![0xfe],
      ("unassigned_33", _) => vec![33],
      ("reserved_5", _) => vec![5],
      (other, None) => panic!("unexpected form {other}"),
    };
    contents.extend_from_slice(&NONCE.to_le_bytes());
    contents.resize(contents.len() + v.payload_len - 8, 0);
    assert_eq!(contents.len(), v.contents_len);
    let decoded = decode_v2(&contents, &ctx(70240));
    let label = format!("{} {}", v.form, v.payload_len);
    match v.core.as_str() {
      "accept" => assert_eq!(
        decoded,
        Ok(DecodedMsg {
          msg: P2pMsg::Ping(Ping { nonce: NONCE }),
          consumed: 8,
        }),
        "{label}"
      ),
      "disconnect: packet too large" => assert!(
        matches!(decoded, Err(P2pDecodeError::ContentsTooLarge { .. })),
        "{label}: {decoded:?}"
      ),
      "dropped: invalid message type" if long_form.is_some() => assert!(
        matches!(decoded, Err(P2pDecodeError::InvalidCommand { .. })),
        "{label}: {decoded:?}"
      ),
      "dropped: invalid message type" => assert!(
        matches!(decoded, Err(P2pDecodeError::UnknownShortId { .. })),
        "{label}: {decoded:?}"
      ),
      "accept: Unknown command" => match long_form {
        Some(expected) => assert!(
          matches!(&decoded, Ok(DecodedMsg { msg: P2pMsg::Unknown { command, .. }, .. }) if *command == expected),
          "{label}: {decoded:?}"
        ),
        // A reserved short ID: Core ignores the empty command and keeps the
        // peer; base-sdk drops the message, which keeps the peer too.
        None => assert!(
          matches!(decoded, Err(P2pDecodeError::UnknownShortId { .. })),
          "{label}: {decoded:?}"
        ),
      },
      other => panic!("{label}: unexpected outcome {other}"),
    }
  }
}

/// The V1 commands of the corpus, by name.
fn v1_commands() -> std::collections::HashMap<String, CommandString> {
  corpus()
    .vectors::<MsgVector>("v1_commands")
    .into_iter()
    .map(|v| {
      let mut bytes = [0u8; 12];
      bytes.copy_from_slice(&vec_from_hex(&v.command));
      (v.name, CommandString::from_bytes(bytes))
    })
    .collect()
}

/// Core's V1 transport drops a message whose command breaks
/// `IsCommandValid`; the handlers never see it, so no gate counts it.
#[rstest]
fn v1_commands_are_checked_as_core() {
  let commands = v1_commands();
  for v in corpus().vectors::<MsgVector>("v1_commands") {
    let command = commands[&v.name];
    let decoded = P2pMsg::decode_with_policy(&command, &vec_from_hex(&v.raw), &ctx(70240));
    match v.core.as_str() {
      "dropped" => assert_eq!(decoded, Err(P2pDecodeError::InvalidCommand { command }), "{}", v.name),
      "accept: Unknown command" => assert!(
        matches!(&decoded, Ok(DecodedMsg { msg: P2pMsg::Unknown { command: c, .. }, .. }) if *c == command),
        "{}: {decoded:?}",
        v.name
      ),
      other => panic!("{}: unexpected outcome {other}", v.name),
    }
  }
}

/// A V2 policy tells a frame Core drops from a payload a handler rejects,
/// and knows the command of the latter (from source, `GetMessageType`).
#[rstest]
fn v2_type_errors_differ_from_payload_errors() {
  assert_eq!(split_v2(&[]), Err(P2pDecodeError::EmptyV2Contents));
  assert_eq!(
    split_v2(b"\0ping"),
    Err(P2pDecodeError::TruncatedV2Type { remaining: 4 })
  );
  // A ping cut short: the transport has typed it, its handler throws.
  let message = split_v2(&[18, 0x2a]).unwrap();
  assert_eq!(
    (message.command(), message.payload()),
    (CommandString::PING, &[0x2a][..])
  );
  assert!(matches!(message.decode(&ctx(70240)), Err(P2pDecodeError::Consensus(_))));
  // Short IDs 29 to 32 are reserved like 5, and 169 is past Dash's slots:
  // none carries a message.
  assert_eq!(split_v2(&[32, 1]), Err(P2pDecodeError::UnknownShortId { id: 32 }));
  assert_eq!(split_v2(&[169]), Err(P2pDecodeError::UnknownShortId { id: 169 }));
}

/// Core reads a pong's nonce only from 8 bytes up; a shorter payload, like a
/// zero nonce, cancels the outstanding ping. A non-zero nonce is compared.
#[rstest]
fn pong_reads_its_nonce_as_core() {
  for v in corpus().vectors::<PongVector>("pong") {
    let raw = vec_from_hex(&v.raw);
    let decoded = P2pMsg::decode_with_policy(&CommandString::PONG, &raw, &ctx(70240));
    let DecodedMsg {
      msg: P2pMsg::Pong(Pong { nonce }),
      consumed,
    } = decoded.unwrap_or_else(|e| panic!("{}: {e}", v.name))
    else {
      panic!("{}: not a pong", v.name);
    };
    let expected = raw.first_chunk::<8>().map(|b| u64::from_le_bytes(*b));
    assert_eq!(nonce, expected, "{}", v.name);
    assert_eq!(consumed, if nonce.is_some() { 8 } else { 0 }, "{}", v.name);
    let cancels = matches!(nonce, None | Some(0));
    assert_eq!(cancels, v.core == "ping cancelled", "{}", v.name);
  }
}

/// A header count the payload cannot hold fails at the count, before the
/// decoder reserves memory for it (Opus r1 M-4: a 3 MiB payload claiming
/// 3,145,720 headers would otherwise reserve 80 bytes per header).
#[rstest]
fn header_counts_are_bound_by_the_payload() {
  let mut payload = vec![0xfe, 0xf8, 0xff, 0x2f, 0x00];
  payload.resize(3 * 1024 * 1024, 0);
  let left = payload.len() - 5;
  assert_eq!(
    Headers::decode(&mut &payload[..]),
    Err(DecodeError::CompactSizeExceedsLimit {
      limit: left / 81,
      value: 3_145_720,
    })
  );
  assert_eq!(
    Headers2::decode(&mut &payload[..]),
    Err(DecodeError::CompactSizeExceedsLimit {
      limit: left / 39,
      value: 3_145_720,
    })
  );
}
