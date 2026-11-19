//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special payloads judged by Dash Core, run through the payload decoders.
//!
//! `payload_core.json5` holds crafted payloads with Core's verdict at both
//! pins under both BLS flags; `v24.json5` holds Core-built v24 transactions
//! with Core's JSON for their payloads.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_primitives::{PayloadDecode, SpecialPayload, Transaction};
use dash_types::codec::BaseCodec;

use std::sync::LazyLock;

fn decode_tx(raw: &str) -> Transaction {
  let bytes = dash_dev::vec_from_hex(raw);
  Transaction::decode(&mut &bytes[..]).unwrap()
}

/// The payload, when it decodes and Core's `GetTxPayload` would accept it.
fn accepted(tx: &Transaction) -> Option<PayloadDecode> {
  tx.decode_payload()?.ok().filter(PayloadDecode::is_complete)
}

/// `payload_core.json5`, parsed once.
static CRAFTED: LazyLock<Value> =
  LazyLock::new(|| Corpus::open(env!("CARGO_MANIFEST_DIR"), "payload_core").into_value());

/// The transaction of a crafted case.
fn crafted_tx(name: &str) -> Transaction {
  decode_tx(CRAFTED[name]["raw"].as_str().unwrap())
}

fn reencode(payload: &SpecialPayload) -> Vec<u8> {
  let mut buf = Vec::new();
  match payload {
    SpecialPayload::ProviderRegister(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateService(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateRegistrar(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateRevoke(p) => p.encode(&mut buf),
    SpecialPayload::CoinbaseCommitment(p) => p.encode(&mut buf),
    SpecialPayload::QuorumCommitment(p) => p.encode(&mut buf),
    SpecialPayload::MnhfSignal(p) => p.encode(&mut buf),
    SpecialPayload::AssetLock(p) => p.encode(&mut buf),
    SpecialPayload::AssetUnlock(p) => p.encode(&mut buf),
    SpecialPayload::ProviderDissolve(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateShare(p) => p.encode(&mut buf),
    SpecialPayload::ProviderUpdateSharedRegistrar(p) => p.encode(&mut buf),
    other => panic!("no encoding for {other:?}"),
  }
  buf
}

/// Payloads Core accepts encode as follows: the coinbase and asset-unlock
/// signatures as their raw wire bytes, whichever scheme they are canonical
/// in, and an always-basic field holding legacy-only bytes as zeros, as Core
/// serializes it.
///
/// Core would write those signatures under its flag at the time, as zeros
/// when canonical only in the other scheme. No consensus result sees the
/// difference: a txid covers the raw payload, Core re-serializes a CbTx only
/// when mining a fresh one, and an asset unlock's signed hash clears the
/// signature first.
#[test]
fn payloads_encode_as_core_serializes_them() {
  let names = [
    "cbtx_v3_sig_legacy",
    "cbtx_v3_sig_basic",
    "assetunlock_v1_sig_legacy",
    "assetunlock_v1_sig_basic",
  ];
  for name in names {
    let tx = crafted_tx(name);
    assert_eq!(
      &reencode(accepted(&tx).unwrap().payload()),
      tx.extra_payload(),
      "{name}"
    );
  }
  // Both fields follow 34 bytes: MnHF's version, version bit and quorum hash;
  let (name, len) = ("mnhf_sig_legacy", 96);
  let tx = crafted_tx(name);
  let mut expected = tx.extra_payload().clone();
  expected[34..34 + len].fill(0);
  assert_eq!(reencode(accepted(&tx).unwrap().payload()), expected, "{name}");
}

/// Core's `CFinalCommitment::IsNull` counts a BLS field that decoded invalid,
/// its bytes canonical only in the other scheme, as absent (A1 quirk 36).
#[test]
fn null_commitment_ignores_fields_of_the_other_scheme() {
  for (name, null) in [
    ("qctx_v1_basic", true),
    ("qctx_v3_basic", false),
    ("qctx_v3_legacy", true),
  ] {
    let mut raw = dash_dev::vec_from_hex(CRAFTED[name]["raw"].as_str().unwrap());
    // The crafted verification vector hash is 32 bytes of 0x06.
    let at = raw.windows(32).position(|w| w == [6u8; 32]).unwrap();
    raw[at..at + 32].fill(0);
    let tx = Transaction::decode(&mut &raw[..]).unwrap();
    let SpecialPayload::QuorumCommitment(p) = accepted(&tx).unwrap().into_payload() else {
      panic!("{name}")
    };
    assert_eq!(p.commitment().is_null(), null, "{name}");
  }
}
