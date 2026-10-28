//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold signature recovery via Lagrange interpolation.

use super::error::BlsError;
use super::scheme_ops::BlsScheme;
use super::share_ops::BlsSigShare;
use super::sig_basic::BlsSignature;
use super::BlsShareId;
use crate::prelude::*;

impl<S: BlsScheme> BlsSignature<S> {
  /// Recover a full signature from threshold signature shares via Lagrange
  /// interpolation in G2.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientShares` if fewer than 2 shares are provided,
  /// `ZeroScalar`/`DuplicateShareId` on bad ids, or `InvalidSignature`
  /// when a share fails to decode.
  pub fn recover_shares(shares: &[&BlsSigShare<S>]) -> Result<Self, BlsError> {
    let ids: Vec<&BlsShareId> = shares.iter().map(|s| s.id()).collect();
    let sigs: Vec<&S::InnerSig> = shares.iter().map(|s| &s.signature().0).collect();

    S::recover_sig_shares(&ids, &sigs).map(BlsSignature::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::scheme_ops::BlsScheme;
  use crate::bls::tests::{make_id, sequential_ids, MSG_DEADBEEF, RSEED};
  use crate::bls::{BlsError, BlsScChia, BlsScIetf, BlsSecretKey, BlsShareId, BlsSigShare, BlsSignature, BlsSkShare};
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus, Value};
  use getrandom::SysRng;
  use hex_conservative::DisplayHex;
  use rand_core::UnwrapErr;
  use rstest::rstest;

  fn assert_threshold_split_recover<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let pk = sk.public_key();
    let ids = sequential_ids(5);

    let shares = sk.split(3, &ids, &mut UnwrapErr(SysRng)).unwrap();
    assert_eq!(shares.len(), 5);

    // Any threshold-sized subset recovers the master signature. Comparing
    // against the master's own signature, not just verifying, is what pins
    // interpolation to the right point rather than to a self-consistent one.
    let msg = &MSG_DEADBEEF;
    let sig_shares: Vec<BlsSigShare<S>> = shares[..3].iter().map(|s| s.sign_digest(msg)).collect();
    let refs: Vec<&BlsSigShare<S>> = sig_shares.iter().collect();
    let recovered = BlsSignature::<S>::recover_shares(&refs).unwrap();
    assert!(pk.verify_digest(msg, &recovered).is_ok());
    assert_eq!(recovered.to_bytes(), sk.sign_digest(msg).to_bytes());

    // A different subset recovers the identical signature.
    let sig_shares2: Vec<BlsSigShare<S>> = shares[2..5].iter().map(|s| s.sign_digest(msg)).collect();
    let refs2: Vec<&BlsSigShare<S>> = sig_shares2.iter().collect();
    let recovered2 = BlsSignature::<S>::recover_shares(&refs2).unwrap();
    assert_eq!(recovered.to_bytes(), recovered2.to_bytes());
  }

  #[rstest]
  #[case::chia(assert_threshold_split_recover::<BlsScChia>)]
  #[case::ietf(assert_threshold_split_recover::<BlsScIetf>)]
  fn threshold_split_and_recover(#[case] assertion: fn()) {
    assertion();
  }

  /// Interpolating fewer than `threshold` shares still yields a point, so the
  /// guard against a short quorum is that the result fails verification.
  fn assert_sub_threshold_does_not_verify<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let pk = sk.public_key();
    let shares = sk.split(3, &sequential_ids(5), &mut UnwrapErr(SysRng)).unwrap();
    let msg = &MSG_DEADBEEF;
    let signed: Vec<BlsSigShare<S>> = shares.iter().map(|s| s.sign_digest(msg)).collect();

    let below = BlsSignature::<S>::recover_shares(&[&signed[0], &signed[1]]).unwrap();
    assert!(pk.verify_digest(msg, &below).is_err());

    let at = BlsSignature::<S>::recover_shares(&[&signed[0], &signed[2], &signed[4]]).unwrap();
    assert!(pk.verify_digest(msg, &at).is_ok());
  }

  #[rstest]
  #[case::chia(assert_sub_threshold_does_not_verify::<BlsScChia>)]
  #[case::ietf(assert_sub_threshold_does_not_verify::<BlsScIetf>)]
  fn sub_threshold_recovery_does_not_verify(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_insufficient_shares_rejected<S: BlsScheme>() {
    assert!(matches!(
      BlsSignature::<S>::recover_shares(&[]),
      Err(BlsError::InsufficientShares)
    ));

    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let ids = sequential_ids(3);
    let shares = sk.split(2, &ids, &mut UnwrapErr(SysRng)).unwrap();
    let one = shares[0].sign_digest(&MSG_DEADBEEF);
    assert!(matches!(
      BlsSignature::<S>::recover_shares(&[&one]),
      Err(BlsError::InsufficientShares)
    ));
  }

  #[rstest]
  #[case::chia(assert_insufficient_shares_rejected::<BlsScChia>)]
  #[case::ietf(assert_insufficient_shares_rejected::<BlsScIetf>)]
  fn recover_rejects_insufficient_shares(#[case] assertion: fn()) {
    assertion();
  }

  /// The two slices are paired, so a length mismatch is a fault of its own
  /// rather than a short quorum.
  fn assert_mismatched_id_count_rejected<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::from_ikm(&RSEED[0]).unwrap();
    let ids = sequential_ids(3);
    let shares = sk.split(2, &ids, &mut UnwrapErr(SysRng)).unwrap();
    let signed: Vec<BlsSigShare<S>> = shares.iter().map(|s| s.sign_digest(&MSG_DEADBEEF)).collect();

    let id_refs: Vec<&BlsShareId> = ids.iter().collect();
    let sig_refs: Vec<&S::InnerSig> = signed[..2].iter().map(|s| &s.signature().0).collect();
    assert_eq!(S::recover_sig_shares(&id_refs, &sig_refs), Err(BlsError::CountMismatch));
  }

  #[rstest]
  #[case::chia(assert_mismatched_id_count_rejected::<BlsScChia>)]
  #[case::ietf(assert_mismatched_id_count_rejected::<BlsScIetf>)]
  fn recover_rejects_mismatched_id_count(#[case] assertion: fn()) {
    assertion();
  }

  /// Shares come from the corpus rather than a fresh `split`, whose random
  /// polynomial leaves nothing to assert against but a round trip. `full_sig`
  /// cross-checks interpolation against the master's own signature.
  fn assert_recovery_matches_vectors<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_threshold")
      .scope(scheme)
      .into_value();
    let case = &f["recover_sig"];
    let inputs = &case["inputs"];
    let threshold = inputs["t"].as_u64().unwrap() as usize;
    let total = inputs["n"].as_u64().unwrap() as usize;
    let msg: [u8; 32] = arr_from_hex(inputs["msg"].as_str().unwrap());

    // The polynomial's constant term is the master secret key.
    let master = BlsSecretKey::<S>::from_bytes(&arr_from_hex(inputs["master_sks"][0].as_str().unwrap())).unwrap();

    for out in case["outputs"].as_array().unwrap() {
      let sk_shares = out["sk_shares"].as_array().unwrap();
      let sig_shares = out["sig_shares"].as_array().unwrap();
      assert_eq!(sk_shares.len(), total);
      assert_eq!(sig_shares.len(), total);

      // Each share key signs the message to its recorded signature share.
      for (i, (sk_hex, sig_hex)) in sk_shares.iter().zip(sig_shares).enumerate() {
        let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(sk_hex.as_str().unwrap())).unwrap();
        let share = BlsSkShare::new(make_id(i as u32 + 1), sk);
        let signed = share.sign_digest(&msg);
        assert_eq!(
          signed.signature().to_bytes().to_lower_hex_string(),
          sig_hex.as_str().unwrap()
        );
      }

      // Recover from the recorded shares, so interpolation is pinned even if
      // share signing were to regress.
      let ids = out["recover_ids"].as_array().unwrap();
      assert_eq!(ids.len(), threshold);
      let picked: Vec<BlsSigShare<S>> = ids
        .iter()
        .map(|id| {
          let i = id.as_u64().unwrap() as usize;
          let sig = BlsSignature::<S>::from_bytes(&arr_from_hex(sig_shares[i - 1].as_str().unwrap())).unwrap();
          BlsSigShare::new(make_id(i as u32), sig)
        })
        .collect();
      let refs: Vec<&BlsSigShare<S>> = picked.iter().collect();
      let recovered = BlsSignature::<S>::recover_shares(&refs).unwrap();

      let expected = out["recovered_sig"].as_str().unwrap();
      assert_eq!(recovered.to_bytes().to_lower_hex_string(), expected);
      assert_eq!(
        out["full_sig"].as_str().unwrap(),
        expected,
        "recovery must match the master"
      );
      assert_eq!(master.sign_digest(&msg).to_bytes().to_lower_hex_string(), expected);
    }
  }

  #[rstest]
  #[case::chia(assert_recovery_matches_vectors::<BlsScChia>, "chia")]
  #[case::ietf(assert_recovery_matches_vectors::<BlsScIetf>, "ietf")]
  fn recovery_matches_vectors(#[case] assertion: fn(&str), #[case] scheme: &str) {
    assertion(scheme);
  }
}
