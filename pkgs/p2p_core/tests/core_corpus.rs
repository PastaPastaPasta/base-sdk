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
  CFCheckpt, CFHeaders, CFilter, CmpctBlock, CommandString, FilterLoad, Headers2, Magic, MerkleBlock, P2pDecodeError,
  P2pMsg, ProtoCtx, ProtocolVersion, SendCmpct, V1FrameError, V1Header,
};
use dash_pkc::bls::BlsCtx;
use dash_primitives::{Block, BlockHeader};
use dash_types::codec::BaseCodec;
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
  let mut bytes = [0u8; 12];
  bytes[..name.len()].copy_from_slice(name.as_bytes());
  CommandString::from_bytes(bytes)
}

/// The probes negotiated common version 70240 at both releases.
fn ctx() -> ProtoCtx {
  ProtoCtx::new(ProtocolVersion::V23_1, BlsCtx::BASIC)
}

fn open(name: &str) -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), name)
}

/// Decodes with the command's own codec and re-encodes, for a message Core
/// has no handler for.
fn typed_round_trip<T: BaseCodec>(raw: &[u8]) -> bool {
  let mut cursor = raw;
  let value = T::decode(&mut cursor).unwrap();
  let mut buf = Vec::new();
  value.encode(&mut buf);
  cursor.is_empty() && buf == raw
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
    if let P2pMsg::Unread(_) = d.msg {
      let ok = match m.command.as_str() {
        "merkleblock" => typed_round_trip::<MerkleBlock>(&raw),
        "cfilter" => typed_round_trip::<CFilter>(&raw),
        "cfheaders" => typed_round_trip::<CFHeaders>(&raw),
        "cfcheckpt" => typed_round_trip::<CFCheckpt>(&raw),
        other => panic!("{other} has no handler"),
      };
      assert!(ok, "{label}");
      continue;
    }
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
      .map(|tx| {
        let mut txid = Vec::new();
        tx.hash().encode(&mut txid);
        cmpct.short_id(&txid.try_into().unwrap())
      })
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

#[rstest]
fn handler_verdicts_are_cores() {
  let cases: Vec<Case> = open("core_verdicts").value("cases");
  assert!(cases.len() > 150);
  for c in &cases {
    let label = format!("{} at {}", c.name, c.pin);
    for (cmd, raw) in &c.pre {
      P2pMsg::decode_with_policy(&command(cmd), &raw.bytes(), &ctx()).unwrap_or_else(|e| panic!("{label}: {e}"));
    }
    let r = P2pMsg::decode_with_policy(&command(&c.command), &c.raw.bytes(), &ctx());
    match c.read.as_str() {
      "throw" | "catch" => match r {
        Err(P2pDecodeError::TooManyEntries { .. } | P2pDecodeError::PayloadTooLarge { .. }) | Ok(_) => {
          panic!("{label}: base-sdk read {r:?}, Core threw")
        }
        Err(_) => {}
      },
      "too_many" => assert!(
        matches!(r, Err(P2pDecodeError::TooManyEntries { .. })),
        "{label}: {r:?}"
      ),
      "unread" => assert_eq!(r.unwrap().msg, P2pMsg::Unread(command(&c.command)), "{label}"),
      "read" => assert!(
        !r.unwrap_or_else(|e| panic!("{label}: {e}")).msg.is_unknown(),
        "{label}"
      ),
      "gated" => {}
      other => panic!("{label}: label {other}"),
    }
  }
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
  // Any non-zero byte is true; a version other than 1 is read, then ignored.
  let P2pMsg::SendCmpct(SendCmpct {
    high_bandwidth,
    version,
  }) = read("sendcmpct_hb02_v1")
  else {
    panic!("sendcmpct")
  };
  assert!(high_bandwidth.get() && version == 1);
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
    let mut header = [0u8; V1Header::SIZE];
    header.copy_from_slice(&bytes[..V1Header::SIZE]);
    let header = V1Header::from_bytes(&header);
    let verdict = header
      .check(regtest)
      .and_then(|()| header.check_payload(&bytes[V1Header::SIZE..]));
    let logged = |s: &str| f.log.iter().any(|l| l.contains(s));
    match verdict {
      Err(e @ V1FrameError::WrongMagic { .. }) => {
        assert!(
          e.disconnects() && f.core == "disconnect" && logged("Wrong MessageStart"),
          "{}",
          f.name
        )
      }
      Err(e @ V1FrameError::TooLarge { .. }) => {
        assert!(
          e.disconnects() && f.core == "disconnect" && logged("Size too large"),
          "{}",
          f.name
        )
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
