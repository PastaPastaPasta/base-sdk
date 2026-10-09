//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Header message decode benchmarks over Core-built replies.

#![expect(clippy::unwrap_used, reason = "benchmarks rely on trusted test vectors")]

use dash_dev::{vec_from_hex, Corpus};
use dash_p2p_core::{CommandString, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use divan::{black_box, Bencher};

#[derive(::serde::Deserialize)]
struct Reply {
  name: String,
  raw: String,
}

/// The `getheaders2` replies mainnet and testnet nodes built, by name.
fn replies() -> Vec<(String, Vec<u8>)> {
  let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "core_headers2");
  let entries: Vec<Reply> = corpus.value("networks");
  entries.into_iter().map(|e| (e.name, vec_from_hex(&e.raw))).collect()
}

#[divan::bench(args = ["mainnet", "testnet"])]
fn headers2_decode(bencher: Bencher, net: &str) {
  let (_, payload) = replies().into_iter().find(|(name, _)| name.starts_with(net)).unwrap();
  let ctx = ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC);
  bencher
    .counter(1u32)
    .bench(|| black_box(P2pMsg::decode_with_policy(&CommandString::HEADERS2, black_box(&payload), &ctx).unwrap()));
}

fn main() {
  divan::main();
}
