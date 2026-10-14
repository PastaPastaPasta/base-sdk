//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's reads of the CoinJoin and governance messages against
//! base-sdk's.

#![cfg(feature = "serde")]
#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, DsSignedInputs, P2pDecodeError, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_params::{ChainParams, ChainParamsBuilder, NetworkKind, Release};
use dash_pkc::bls::BlsCtx;
use dash_types::{Hashable, Numeric};
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
struct Case {
  name: String,
  command: String,
  /// The stream version, the peer's common version.
  version: i32,
  raw: Raw,
  core: Core,
}

#[derive(::serde::Deserialize)]
struct Core {
  ok: bool,
  consumed: Option<usize>,
  reenc: Option<String>,
  class: Option<String>,
  /// `GetHash()`, or a mixed transaction's txid.
  hash: Option<String>,
  /// `GetSignatureHash()`.
  #[serde(rename = "signHash")]
  sign_hash: Option<String>,
}

/// How Core's handler takes a refusal, where it tells them apart: `dss`'s
/// count over the pool gets a reply, `govsync`'s hash cut short is logged
/// and its filter refused scores the peer; any other failed read.
#[derive(Debug, PartialEq)]
enum Refusal {
  Reply,
  Log,
  Score,
  Read,
}

impl Refusal {
  fn of_class(class: Option<&str>) -> Self {
    match class {
      Some("err_maximum") => Self::Reply,
      Some("short_hash") => Self::Log,
      Some("filter") => Self::Score,
      _ => Self::Read,
    }
  }
}

/// The bytes base-sdk read, what it writes back and its hashes.
struct Read {
  consumed: usize,
  reenc: Vec<u8>,
  hash: Option<Vec<u8>>,
  sign_hash: Option<Vec<u8>>,
}

fn le<H: Numeric>(h: H) -> Option<Vec<u8>> {
  Some(h.to_lendian().as_ref().to_vec())
}

/// base-sdk's read of `c`, with the node's checks around it (the judge's
/// chain is mainnet).
fn read(c: &Case, raw: &[u8], params: &ChainParams) -> Result<Read, Refusal> {
  if c.command == "dss" {
    DsSignedInputs::check_payload(raw, params).map_err(|e| match e {
      P2pDecodeError::TooManyEntries { .. } => Refusal::Reply,
      _ => Refusal::Read,
    })?;
  }
  let ctx = ProtoCtx::new(ProtocolVersion::from_base(c.version), BlsCtx::BASIC);
  let d = P2pMsg::decode_with_policy(&CommandString::from_static(&c.command), raw, &ctx).map_err(|_| {
    match c.command.as_str() {
      "govsync" if raw.len() < 32 => Refusal::Log,
      "govsync" => Refusal::Score,
      _ => Refusal::Read,
    }
  })?;
  let (hash, sign_hash) = match &d.msg {
    P2pMsg::Dsi(m) if !m.fits_pool(params) => return Err(Refusal::Read),
    P2pMsg::GovSync(m) if !m.bloom_filter.is_within_size_constraints() => return Err(Refusal::Score),
    P2pMsg::Dsq(m) => (le(m.hash()), le(m.signature_hash())),
    P2pMsg::Dstx(m) => (le(m.tx.hash()), le(m.signature_hash())),
    P2pMsg::GovObj(m) => (le(m.hash()), le(m.signature_hash())),
    P2pMsg::GovObjVote(m) => (le(m.hash()), le(m.signature_hash())),
    _ => (None, None),
  };
  let mut reenc = Vec::new();
  d.msg.encode_payload(&mut reenc);
  Ok(Read {
    consumed: d.consumed,
    reenc,
    hash,
    sign_hash,
  })
}

#[rstest]
fn coinjoin_and_governance_reads_are_cores() {
  let cases: Vec<Case> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_overlay_iii").value("cases");
  assert!(cases.len() > 200);
  let params = ChainParamsBuilder::new(NetworkKind::Mainnet, Release::V24_0)
    .build()
    .unwrap();
  for c in &cases {
    let label = format!("{} ({} at {})", c.name, c.command, c.version);
    let raw = c.raw.bytes();
    let ours = read(c, &raw, &params);
    let Core {
      ok,
      consumed,
      reenc,
      class,
      hash,
      sign_hash,
    } = &c.core;
    if !ok {
      let want = Refusal::of_class(class.as_deref());
      match ours {
        Err(r) => assert_eq!(r, want, "{label}: Core refused it ({class:?})"),
        Ok(_) => panic!("{label}: Core refused it ({class:?}), base-sdk read it"),
      }
      continue;
    }
    let r = ours.unwrap_or_else(|r| panic!("{label}: Core read it, base-sdk refused ({r:?})"));
    assert_eq!(Some(r.consumed), *consumed, "{label}: bytes read");
    // Core writes back what it read, but for a boolean byte other than 0
    // or 1, which it writes as 1 and hashes so.
    let want = reenc
      .as_deref()
      .map_or_else(|| raw[..r.consumed].to_vec(), vec_from_hex);
    assert_eq!(r.reenc, want, "{label}: write-back");
    assert_eq!(r.hash, hash.as_deref().map(vec_from_hex), "{label}: hash");
    assert_eq!(
      r.sign_hash,
      sign_hash.as_deref().map(vec_from_hex),
      "{label}: sign hash"
    );
  }
}
