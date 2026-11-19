//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signatures Dash Core made, checked over the payloads' sign hashes.
//!
//! `sighash.json5` holds special transactions from Core-built chains with
//! the keys their signers held. A sign hash is right when Core's signature
//! verifies over it: a BLS signature under the signer's key, an ECDSA one by
//! recovering a key whose id the signer owns, as Core's `CHashSigner` does.
//! The corpus also holds asset unlocks with Core's txid and instance hash.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_primitives::Transaction;
use dash_types::codec::BaseCodec;
use dash_types::Hashable;

fn corpus(section: &str) -> Value {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "sighash").into_value()[section].take()
}

fn decode_tx(raw: &str) -> Transaction {
  let bytes = dash_dev::vec_from_hex(raw);
  Transaction::decode(&mut &bytes[..]).unwrap()
}

/// Asset unlocks: the txid is Core's, and the instance hash is the one Core
/// printed for a version-2 unlock, the txid otherwise.
#[test]
fn asset_unlock_txids_match_core() {
  let entries = corpus("stable_txid");
  let entries = entries.as_object().unwrap();
  let mut stable = 0;
  for (txid, entry) in entries {
    let tx = decode_tx(entry["raw"].as_str().unwrap());
    let instance = entry
      .get("instance_hash")
      .map_or(txid.as_str(), |h| h.as_str().unwrap());
    assert_eq!(tx.hash().to_string(), *txid, "{txid}: txid");
    assert_eq!(tx.instance_hash().to_string(), instance, "{txid}: instance hash");
    assert_eq!(
      tx.has_stable_txid(),
      entry.get("instance_hash").is_some(),
      "{txid}: stable"
    );
    stable += usize::from(tx.has_stable_txid());
  }
  assert!(stable >= 2 && entries.len() > stable);
}
