//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Messages Dash Core built, and Core's handler verdicts, against base-sdk.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{
  CmpctBlock, CommandString, FilterLoad, Headers2, Magic, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion, SendCmpct,
  V1FrameError, V1Header,
};
use dash_pkc::bls::BlsCtx;
use dash_primitives::{Block, BlockHeader};
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::Hashable;
use rstest::rstest;

/// Hex, or a list of hex and `{"b", "n"}` byte runs (the corpus RLE).
#[derive(::serde::Deserialize)]
#[serde(untagged)]
enum Raw {
  Hex(String),
  Runs(Vec<Run>),
}

#[derive(::serde::Deserialize)]
#[serde(untagged)]
enum Run {
  Hex(String),
  Repeat { b: String, n: usize },
}

impl Raw {
  fn bytes(&self) -> Vec<u8> {
    match self {
      Self::Hex(h) => vec_from_hex(h),
      Self::Runs(runs) => runs
        .iter()
        .flat_map(|r| match r {
          Run::Hex(h) => vec_from_hex(h),
          Run::Repeat { b, n } => vec![vec_from_hex(b)[0]; *n],
        })
        .collect(),
    }
  }
}

#[derive(::serde::Deserialize)]
struct Message {
  pin: String,
  source: String,
  command: String,
  raw: Raw,
}

#[derive(::serde::Deserialize)]
struct Compact {
  cmpctblock: String,
  block: String,
}

#[derive(::serde::Deserialize)]
struct Header2Msg {
  #[serde(default)]
  name: String,
  #[serde(default)]
  pin: String,
  mode: String,
  raw: String,
}

#[derive(::serde::Deserialize)]
struct Case {
  pin: String,
  name: String,
  command: String,
  read: String,
  raw: Raw,
  pre: Vec<(String, Raw)>,
  /// Bytes Core's handler reads, for read cases.
  consumed: Option<usize>,
  /// Core's exception text, for rejected cases.
  exception: Option<String>,
  /// The version this probe connection announced, when not 70242.
  version: Option<i32>,
  replies: Vec<String>,
}

#[derive(::serde::Deserialize)]
struct Framing {
  name: String,
  core: String,
  log: Vec<String>,
  pongs: Vec<String>,
  frame: Raw,
}

fn command(name: &str) -> CommandString {
  CommandString::from_static(name)
}

/// The probe negotiated common version 70242 with v24.0, the parity reference.
fn ctx() -> ProtoCtx {
  ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC)
}

fn open(name: &str) -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), name)
}

/// Commands whose base-sdk shape another task owns (DDE-SWEEP §5), with the
/// divergence: their decode stops short of Core's request.
const OTHER_OWNERS: [(&str, &str); 1] = [("govsync", "BS9b: govsync reads only the bloom filter data")];

#[rstest]
fn every_message_core_sent_round_trips() {
  let messages: Vec<Message> = open("core_messages").value("messages");
  assert!(messages.len() > 700);
  for m in &messages {
    let raw = m.raw.bytes();
    let label = format!("{} {} from {}", m.command, m.source, m.pin);
    let d = P2pMsg::decode_with_policy(&command(&m.command), &raw, &ctx()).unwrap_or_else(|e| panic!("{label}: {e}"));
    assert!(!d.msg.is_unknown(), "{label}");
    let mut buf = Vec::new();
    d.msg.encode_payload(&mut buf);
    assert_eq!(buf, raw[..d.consumed], "{label}");
    if OTHER_OWNERS.iter().any(|(cmd, _)| *cmd == m.command) {
      continue;
    }
    assert_eq!(d.consumed, raw.len(), "{label}: Core sends no trailing bytes");
  }
}

#[rstest]
fn short_ids_are_cores() {
  let pairs: Vec<Compact> = open("core_messages").value("compact");
  assert!(pairs.len() > 100);
  let mut with_short_ids = 0;
  for p in &pairs {
    let cmpct = CmpctBlock::decode(&mut &vec_from_hex(&p.cmpctblock)[..]).unwrap();
    let block = Block::decode(&mut &vec_from_hex(&p.block)[..]).unwrap();
    assert_eq!(cmpct.header, block.header);
    // Core prefills the coinbase alone and sends a short ID for every other.
    assert_eq!(cmpct.prefilled.len(), 1);
    assert_eq!(
      (cmpct.prefilled[0].index, &cmpct.prefilled[0].tx),
      (0, &block.transactions[0])
    );
    let want: Vec<_> = block.transactions[1..]
      .iter()
      .map(|tx| cmpct.short_id(tx.hash().as_bytes()))
      .collect();
    assert_eq!(cmpct.short_ids, want);
    with_short_ids += usize::from(!want.is_empty());
  }
  assert!(with_short_ids > 0, "no compact block carried a short ID");
}

fn check_headers2(raw: &[u8], mode: &str, label: &str) -> Headers2 {
  let d = P2pMsg::decode_with_policy(&CommandString::HEADERS2, raw, &ctx()).unwrap();
  let P2pMsg::Headers2(msg) = d.msg else {
    panic!("{label}: not headers2")
  };
  assert_eq!(d.consumed, raw.len(), "{label}");
  let mut buf = Vec::new();
  msg.encode(&mut buf);
  assert_eq!(buf, raw, "{label}: re-encode");
  let headers: Vec<BlockHeader> = msg.block_headers().copied().collect();
  let encode = |m: Headers2| {
    let mut b = Vec::new();
    m.encode(&mut b);
    b == raw
  };
  let (reply, announce) = (encode(Headers2::reply(&headers)), encode(Headers2::announce(&headers)));
  match mode {
    "reply" => assert!(reply, "{label}: reply mode"),
    "announce" => assert!(announce, "{label}: announcement mode"),
    _ => assert!(reply || announce, "{label}: either mode"),
  }
  for (i, pair) in headers.windows(2).enumerate() {
    assert_eq!(pair[1].prev_hash, pair[0].hash(), "{label}: header {}", i + 1);
    assert!(
      msg.is_prev_hash_derived(i + 1),
      "{label}: Core compresses every later prev hash"
    );
  }
  msg
}

#[rstest]
fn core_headers2_round_trip_in_their_mode() {
  let corpus = open("core_headers2");
  let capture: Vec<Header2Msg> = corpus.value("capture");
  let mut modes = std::collections::BTreeSet::new();
  for (i, m) in capture.iter().enumerate() {
    check_headers2(&vec_from_hex(&m.raw), &m.mode, &format!("capture {i} from {}", m.pin));
    modes.insert(m.mode.clone());
  }
  assert!(modes.contains("reply") && modes.contains("announce"));
  let oracle: Vec<Header2Msg> = corpus.value("oracle");
  assert_eq!(oracle.len(), 4);
  for m in &oracle {
    let msg = check_headers2(&vec_from_hex(&m.raw), &m.mode, &m.name);
    assert_eq!(msg.headers.len(), 300, "{}", m.name);
  }
}

/// Cases Core reads where base-sdk is strict by design (BSX, DEC-98): a
/// `sendcmpct` flag other than 0 or 1, which Core reads as `true` (D-11).
const STRICT: [&str; 1] = ["sendcmpct_hb02_v1"];

/// Commands Core has no handler for and ignores unread. base-sdk types them
/// both ways, so the node ignores them before decoding (D-14).
const IGNORED_BY_CORE: [&str; 4] = ["merkleblock", "cfilter", "cfheaders", "cfcheckpt"];

#[rstest]
fn handler_verdicts_are_cores() {
  let cases: Vec<Case> = open("core_verdicts").value("cases");
  assert!(cases.len() > 80);
  for c in &cases {
    let label = format!("{} at {}", c.name, c.pin);
    for (cmd, raw) in &c.pre {
      P2pMsg::decode_with_policy(&command(cmd), &raw.bytes(), &ctx()).unwrap_or_else(|e| panic!("{label}: {e}"));
    }
    let ctx = ProtoCtx::new(ProtocolVersion::new(c.version.unwrap_or(70242)), BlsCtx::BASIC);
    let r = P2pMsg::decode_with_policy(&command(&c.command), &c.raw.bytes(), &ctx);
    match c.read.as_str() {
      // The verdict only: no Core logic observes the error class or where the
      // read stopped (DEC-98).
      "throw" | "catch" => assert!(
        matches!(r, Err(P2pDecodeError::Consensus(_))),
        "{label}: base-sdk {r:?}, Core threw {:?}",
        c.exception
      ),
      "too_many" => assert!(
        matches!(r, Err(P2pDecodeError::TooManyEntries { .. })),
        "{label}: {r:?}"
      ),
      // Core's verdict is to ignore the message whatever its payload; base-sdk
      // reads it, the probe's garbage included.
      "unread" => assert!(IGNORED_BY_CORE.contains(&c.command.as_str()), "{label}"),
      "read" if STRICT.contains(&c.name.as_str()) => assert!(
        matches!(r, Err(P2pDecodeError::Consensus(DecodeError::InvalidValue { .. }))),
        "{label}: {r:?}"
      ),
      "read" => {
        let d = r.unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(!d.msg.is_unknown(), "{label}");
        assert_eq!(Some(d.consumed), c.consumed, "{label}: bytes read");
      }
      "gated" => {}
      other => panic!("{label}: label {other}"),
    }
  }
}

/// Core requests an inventory type it knows, type 34 included.
#[rstest]
fn inventory_types_core_knows_are_requested() {
  let cases: Vec<Case> = open("core_verdicts").value("cases");
  let mut checked = 0;
  for c in cases.iter().filter(|c| c.name.starts_with("inv_type")) {
    let ctx = ProtoCtx::new(ProtocolVersion::new(c.version.unwrap_or(70242)), BlsCtx::BASIC);
    let P2pMsg::Inv(inv) = P2pMsg::decode_with_policy(&CommandString::INV, &c.raw.bytes(), &ctx)
      .unwrap()
      .msg
    else {
      panic!("{}", c.name)
    };
    let requested = c.replies.iter().any(|r| r == "getdata");
    assert!(requested, "{}", c.name);
    assert!(inv.inventory[0].inv_type.is_known(), "{}", c.name);
    checked += 1;
  }
  assert_eq!(checked, 3);
}

#[rstest]
fn handler_values_after_the_read() {
  let cases: Vec<Case> = open("core_verdicts").value("cases");
  let read = |name: &str| {
    let c = cases.iter().find(|c| c.name == name).unwrap();
    P2pMsg::decode_with_policy(&command(&c.command), &c.raw.bytes(), &ctx())
      .unwrap()
      .msg
  };
  // Core reads both and then penalises the hash function count above 50.
  for (name, funcs) in [("filterload_funcs_50", 50), ("filterload_funcs_51", 51)] {
    let P2pMsg::FilterLoad(FilterLoad { hash_funcs, .. }) = read(name) else {
      panic!("{name}")
    };
    assert_eq!(hash_funcs, funcs);
  }
  // A version other than 1 is read, then ignored.
  let P2pMsg::SendCmpct(SendCmpct { version, .. }) = read("sendcmpct_v2") else {
    panic!("sendcmpct")
  };
  assert_eq!(version, 2);
  let P2pMsg::CmpctBlock(cmpct) = read("cmpctblock_prefilled_index_65535") else {
    panic!("cmpctblock")
  };
  assert_eq!(cmpct.prefilled[0].index, u16::MAX);
  let P2pMsg::CmpctBlock(cmpct) = read("cmpctblock_total_65535") else {
    panic!("cmpctblock")
  };
  assert_eq!(cmpct.short_ids.len(), 65_535);
}

#[rstest]
fn v1_framing_is_cores() {
  let framing: Vec<Framing> = open("core_verdicts").value("framing");
  assert_eq!(framing.len(), 6);
  let regtest = Magic::from_bytes([0xfc, 0xc1, 0xb7, 0xdc]);
  for f in &framing {
    let bytes = f.frame.bytes();
    let header = V1Header::from_bytes(bytes.first_chunk().unwrap());
    let verdict = header
      .check(regtest)
      .and_then(|()| header.check_payload(&bytes[V1Header::SIZE..]));
    let logged = |s: &str| f.log.iter().any(|l| l.contains(s));
    match verdict {
      Err(e @ (V1FrameError::WrongMagic { .. } | V1FrameError::TooLarge { .. })) => {
        let why = match e {
          V1FrameError::WrongMagic { .. } => "Wrong MessageStart",
          _ => "Size too large",
        };
        assert!(e.disconnects() && f.core == "disconnect" && logged(why), "{}", f.name);
      }
      Err(e @ (V1FrameError::BadChecksum | V1FrameError::InvalidCommand)) => {
        // Dropped: the peer stays, and only the probe's own sync ping is answered.
        assert!(
          !e.disconnects() && f.core == "accept" && f.pongs.len() == 1,
          "{}",
          f.name
        );
        assert!(logged("Wrong checksum") || logged("Invalid message type"), "{}", f.name);
      }
      Ok(()) => {
        assert_eq!(f.core, "accept", "{}", f.name);
        let unknown = logged("Unknown command");
        assert!(unknown || f.pongs.len() == 2, "{}: Core handled it", f.name);
      }
    }
  }
}
