//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's verifications in `dash_pkc::bls::core` start no thread.
//!
//! blst's high-level verification runs on its thread pool, which it starts on
//! first use. This file holds a single test, so its binary runs nothing else
//! and the thread count it reads moves only with what the test calls. The
//! pooled verify at the end is the control: it must move the count, or the
//! count proves nothing.

#![cfg(all(feature = "bls", target_os = "linux"))]
#![expect(clippy::panic, reason = "test code")]

use dash_pkc::bls::core::{
  verify_insecure, verify_insecure_aggregated, verify_secure_aggregated, BlsPkValue, BlsSigValue, BlsVerdict,
};
use dash_pkc::bls::{
  BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSchemeKind, BlsSecretKey, BlsSignature, BlsValue,
};

/// The threads of this process.
fn threads() -> usize {
  match std::fs::read_dir("/proc/self/task") {
    Ok(dir) => dir.count(),
    Err(e) => panic!("cannot list /proc/self/task: {e}"),
  }
}

/// Keys, messages and signatures for one scheme, every one built before the
/// thread count is first read.
struct Fixture<S: BlsScheme> {
  pks: Vec<BlsPublicKey<S>>,
  msgs: Vec<[u8; 32]>,
  sigs: Vec<BlsSignature<S>>,
  same_msg: BlsSignature<S>,
  secure: BlsSignature<S>,
  distinct: BlsSignature<S>,
}

impl<S: BlsScheme> Fixture<S> {
  fn new() -> Self {
    let sks: Vec<BlsSecretKey<S>> = (0u8..4)
      .map(|i| match BlsSecretKey::from_ikm(&[i + 1; 32]) {
        Ok(sk) => sk,
        Err(e) => panic!("keygen: {e:?}"),
      })
      .collect();
    let pks: Vec<BlsPublicKey<S>> = sks.iter().map(BlsSecretKey::public_key).collect();
    let msgs: Vec<[u8; 32]> = (0u8..4).map(|i| [i ^ 0x5a; 32]).collect();
    let sigs: Vec<BlsSignature<S>> = sks.iter().zip(&msgs).map(|(sk, m)| sk.sign(S::msg_ref(m))).collect();
    let same: Vec<BlsSignature<S>> = sks.iter().map(|sk| sk.sign(S::msg_ref(&msgs[0]))).collect();
    let same_refs: Vec<&BlsSignature<S>> = same.iter().collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
    let built = (
      BlsSignature::aggregate(&same_refs),
      BlsSignature::secure_aggregate(&same_refs, &pk_refs),
      BlsSignature::aggregate(&sig_refs),
    );
    let (Ok(same_msg), Ok(secure), Ok(distinct)) = built else {
      panic!("aggregation failed");
    };
    Self {
      pks,
      msgs,
      sigs,
      same_msg,
      secure,
      distinct,
    }
  }

  /// Run every `core` verification, on passing and failing inputs alike.
  fn verify_core(&self, kind: BlsSchemeKind) {
    let pks: Vec<BlsPkValue> = self.pks.iter().map(|pk| value(&pk.to_bytes(), kind)).collect();
    let pks: Vec<&BlsPkValue> = pks.iter().collect();
    let sig: BlsSigValue = value(&self.sigs[0].to_bytes(), kind);
    let same: BlsSigValue = value(&self.same_msg.to_bytes(), kind);
    let secure: BlsSigValue = value(&self.secure.to_bytes(), kind);
    let distinct: BlsSigValue = value(&self.distinct.to_bytes(), kind);
    let agg_pk: BlsPkValue = match BlsPublicKey::aggregate(&self.pks.iter().collect::<Vec<_>>()) {
      Ok(pk) => value(&pk.to_bytes(), kind),
      Err(e) => panic!("aggregation failed: {e:?}"),
    };
    let (m0, m1) = (&self.msgs[0], &self.msgs[1]);
    let verdicts = [
      verify_insecure(&sig, pks[0], m0, kind),
      verify_insecure(&sig, pks[0], m1, kind),
      verify_insecure(&same, &agg_pk, m0, kind),
      verify_insecure(&same, &agg_pk, m1, kind),
      verify_secure_aggregated(&secure, &pks, m0, kind),
      verify_secure_aggregated(&secure, &pks[1..], m0, kind),
      verify_insecure_aggregated(&distinct, &pks, &self.msgs, kind),
      verify_insecure_aggregated(&distinct, &pks[1..], &self.msgs[1..], kind),
    ];
    let want = [true, false, true, false, true, false, true, false];
    assert_eq!(
      verdicts.map(BlsVerdict::is_valid),
      want,
      "a verdict is wrong: {verdicts:?}"
    );
  }

  /// The legacy verifications on a key outside the G1 subgroup, which run
  /// the relic engine's pairing and its arithmetic.
  fn verify_engine(&self) {
    let kind = BlsSchemeKind::Legacy;
    let exotic: BlsPkValue = value(&G1_OFF_SUBGROUP, kind);
    let pk: BlsPkValue = value(&self.pks[0].to_bytes(), kind);
    let sig: BlsSigValue = value(&self.sigs[0].to_bytes(), kind);
    let m0 = &self.msgs[0];
    let verdicts = [
      verify_insecure(&sig, &exotic, m0, kind),
      verify_insecure_aggregated(&sig, &[&pk, &exotic], &self.msgs[..2], kind),
      verify_secure_aggregated(&sig, &[&pk, &exotic], m0, kind),
    ];
    assert_eq!(verdicts, [BlsVerdict::Invalid; 3]);
  }
}

/// A legacy G1 key on the curve and outside the subgroup, x = 4.
const G1_OFF_SUBGROUP: [u8; 48] = {
  let mut bytes = [0u8; 48];
  bytes[47] = 4;
  bytes
};

/// A canonical object under `kind`.
fn value<K: dash_pkc::bls::BlsWire<N>, const N: usize>(bytes: &[u8; N], kind: BlsSchemeKind) -> BlsValue<K, N> {
  match BlsValue::from_canonical(bytes, kind) {
    Some(value) => value,
    None => panic!("not canonical under {kind:?}"),
  }
}

#[test]
fn core_verify_starts_no_thread() {
  let chia = Fixture::<BlsScChia>::new();
  let ietf = Fixture::<BlsScIetf>::new();

  let before = threads();
  for _ in 0..3 {
    chia.verify_core(BlsSchemeKind::Legacy);
    ietf.verify_core(BlsSchemeKind::Basic);
    chia.verify_engine();
  }
  let after = threads();
  assert_eq!(
    after,
    before,
    "the core verifications started {} threads",
    after.saturating_sub(before)
  );

  // The control: blst's pooled verify starts its pool, so the count moves.
  assert!(ietf.pks[0].verify(&ietf.msgs[0], &ietf.sigs[0]).is_ok());
  let pooled = threads();
  assert!(
    pooled > before,
    "the pooled verify started no thread ({before} -> {pooled}); the count proves nothing"
  );
}
