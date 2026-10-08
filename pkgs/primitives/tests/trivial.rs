//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's trivial-validation vectors at both pins.

#![expect(clippy::panic, clippy::unwrap_used, reason = "test code")]

use dash_dev::{vec_from_hex, Corpus};
use dash_primitives::{PayloadDecode, SpecialPayload, Transaction};
use dash_types::codec::BaseCodec;
use dash_types::{Checkable, Hashable};

/// Core's reasons for a payload `GetTxPayload` rejects, by pin.
const DECODE_FAILURE: &[&str] = &["gettxpayload-fail", "bad-protx-payload"];

/// The version of a provider payload Core decoded past its version.
fn known_protx_version(payload: &SpecialPayload) -> Option<u16> {
  match payload {
    SpecialPayload::ProviderRegister(p) => Some(p.version),
    SpecialPayload::ProviderUpdateService(p) => Some(p.version),
    SpecialPayload::ProviderUpdateRegistrar(p) => Some(p.version),
    SpecialPayload::ProviderUpdateRevoke(p) => Some(p.version),
    _ => None,
  }
}

/// Each row decodes exactly when Core's `GetTxPayload` accepts it, under
/// either BLS flag. A decoded row passes base-sdk's checks or fails
/// with Core's reason, except where Core caps a known version by the
/// deployments at `pindexPrev`, which a context-free check cannot see.
#[test]
fn trivial_vectors_match_core() {
  let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "trivial").into_value();
  let mut rows = 0;
  for (pin, sets) in corpus.as_object().unwrap() {
    for (kind, vectors) in sets.as_object().unwrap() {
      for row in vectors.as_array().unwrap() {
        rows += 1;
        let txid = row[0].as_str().unwrap();
        let label = format!("{pin} {kind} {txid}");
        let raw = vec_from_hex(row[3].as_str().unwrap());
        let tx = Transaction::decode(&mut &raw[..]).unwrap();
        assert_eq!(tx.hash().to_string(), txid, "{label}");
        let expected = (kind == "invalid").then(|| row[4].as_str().unwrap());
        let decode_fails = expected.is_some_and(|reason| DECODE_FAILURE.contains(&reason));
        let decoded = tx.decode_payload().unwrap().ok().filter(PayloadDecode::is_complete);
        assert_eq!(decoded.is_none(), decode_fails, "{label}: decode verdict");
        let Some(decoded) = decoded else { continue };
        let reason = decoded.payload.check().map(|e| e.to_string());
        // A "legacy" row runs before V19, where `GetMax` allows version 1.
        let capped = row[2] == "legacy" && known_protx_version(&decoded.payload).is_some_and(|v| v > 1);
        if capped && expected == Some("bad-protx-version") {
          assert_eq!(reason, None, "{label}");
          continue;
        }
        match (expected, reason) {
          (None, None) => {}
          (Some(want), Some(got)) => assert!(got.starts_with(want), "{label}: {got}, Core {want}"),
          (want, got) => panic!("{label}: base-sdk {got:?}, Core {want:?}"),
        }
      }
    }
  }
  assert_eq!(rows, 2 * (25 + 12));
}
