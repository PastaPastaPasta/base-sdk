//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! `CBLSWorker`'s compositions (`bls/bls_worker.cpp`), on the calling thread.
//!
//! Core's parallel paths combine partial sums in completion order; these
//! fold in input order, Core's `parallel = false` path. The two agree on
//! subgroup inputs, which is all `CBLSWorker` is given outside legacy-flag
//! networks.

use super::{
  aggregate_public_keys_insecure_pair, aggregate_secret_keys_insecure_pair, aggregate_signatures_insecure_pair,
  make_new_key, public_key, public_key_share, secret_key_share, BlsPkValue, BlsSigValue, BlsSkValue,
};
use crate::bls::{BlsSchemeKind, BlsValue, BlsWire};
use crate::prelude::*;

use alloc::collections::BTreeSet;
use rand_core::CryptoRng;

/// `CONTRIBUTION_VERIFY_BATCH_SIZE` (`bls/bls_worker.h:105`).
pub const CONTRIBUTION_VERIFY_BATCH_SIZE: usize = 8;

/// `VerifyVectorHelper` (`bls_worker.cpp:15-27`): every object valid and no
/// two with the same `GetHash()` under `flag`.
pub fn verify_vector<K: BlsWire<N>, const N: usize>(values: &[&BlsValue<K, N>], flag: BlsSchemeKind) -> bool {
  let mut hashes = BTreeSet::new();
  values
    .iter()
    .all(|v| v.is_valid() && hashes.insert(v.serialize_hash(flag)))
}

/// `VerifyVerificationVectors` (`bls_worker.cpp:752-773`): every vector
/// present and as long as the first, every key valid, and no `GetHash()`
/// repeated across them all.
pub fn verify_verification_vectors(vvecs: &[Option<&[BlsPkValue]>], flag: BlsSchemeKind) -> bool {
  let mut hashes = BTreeSet::new();
  let len = vvecs.first().copied().flatten().map(<[_]>::len);
  vvecs.iter().all(|vvec| {
    vvec.is_some_and(|vvec| {
      Some(vvec.len()) == len
        && vvec
          .iter()
          .all(|pk| pk.is_valid() && hashes.insert(pk.serialize_hash(flag)))
    })
  })
}

/// `Aggregator::SyncAggregate`: the first object, then each later one added
/// by the pair `AggregateInsecure`.
fn sync_aggregate<T: Clone>(values: &[&T], pair: impl Fn(&T, &T) -> T) -> Option<T> {
  let (first, rest) = values.split_first()?;
  Some(rest.iter().fold((*first).clone(), |acc, v| pair(&acc, v)))
}

/// `AsyncAggregateHelper` (`bls_worker.cpp:619-635`): invalid when empty or
/// when [`verify_vector`] fails, otherwise the sum in input order.
fn aggregate_helper<K: BlsWire<N>, const N: usize>(
  values: &[&BlsValue<K, N>],
  flag: BlsSchemeKind,
  pair: impl Fn(&BlsValue<K, N>, &BlsValue<K, N>) -> BlsValue<K, N>,
) -> BlsValue<K, N> {
  if !verify_vector(values, flag) {
    return BlsValue::invalid();
  }
  sync_aggregate(values, pair).unwrap_or_else(BlsValue::invalid)
}

/// `CBLSWorker::AggregateSecretKeys`.
pub fn aggregate_secret_keys(values: &[&BlsSkValue], flag: BlsSchemeKind) -> BlsSkValue {
  aggregate_helper(values, flag, aggregate_secret_keys_insecure_pair)
}

/// `CBLSWorker::AggregatePublicKeys`.
pub fn aggregate_public_keys(values: &[&BlsPkValue], flag: BlsSchemeKind) -> BlsPkValue {
  aggregate_helper(values, flag, aggregate_public_keys_insecure_pair)
}

/// `CBLSWorker::AggregateSigs`.
pub fn aggregate_signatures(values: &[&BlsSigValue], flag: BlsSchemeKind) -> BlsSigValue {
  aggregate_helper(values, flag, aggregate_signatures_insecure_pair)
}

/// `VectorAggregator`: the element-wise sums of vectors of one length.
fn sum_vectors(vvecs: &[&[BlsPkValue]]) -> Vec<BlsPkValue> {
  let len = vvecs.first().map_or(0, |v| v.len());
  (0..len)
    .map(|i| {
      let column: Vec<&BlsPkValue> = vvecs.iter().map(|v| &v[i]).collect();
      sync_aggregate(&column, aggregate_public_keys_insecure_pair).unwrap_or_else(BlsPkValue::invalid)
    })
    .collect()
}

/// `CBLSWorker::BuildQuorumVerificationVector` (`bls_worker.cpp:590-605`):
/// `None` when there is no vector or [`verify_verification_vectors`] fails,
/// otherwise the element-wise sums.
pub fn build_quorum_verification_vector(
  vvecs: &[Option<&[BlsPkValue]>],
  flag: BlsSchemeKind,
) -> Option<Vec<BlsPkValue>> {
  if vvecs.is_empty() || !verify_verification_vectors(vvecs, flag) {
    return None;
  }
  let vvecs: Vec<&[BlsPkValue]> = vvecs.iter().copied().collect::<Option<_>>()?;
  Some(sum_vectors(&vvecs))
}

/// `CBLSWorker::BuildPubKeyShare` (`bls_worker.cpp:679-684`): the key share
/// for `id`, invalid when `PublicKeyShare` fails.
pub fn build_pub_key_share(vvec: &[BlsPkValue], id: &[u8; 32]) -> BlsPkValue {
  let mut share = BlsPkValue::invalid();
  public_key_share(&mut share, &vvec.iter().collect::<Vec<_>>(), id);
  share
}

/// `ContributionVerifier::Verify`: the key share `vvec` gives `id` against
/// the share's public key, by the wrapper's `==`.
fn verify_share(id: &[u8; 32], vvec: &[BlsPkValue], share: &BlsSkValue) -> bool {
  let pk = build_pub_key_share(vvec, id);
  pk.is_valid() && pk.core_eq(&public_key(share))
}

/// `CBLSWorker::AsyncVerifyContributionShare` (`bls_worker.cpp:721-745`):
/// `false` for a missing vector or one [`verify_vector`] refuses.
pub fn verify_contribution_share(
  for_id: &[u8; 32],
  vvec: Option<&[BlsPkValue]>,
  share: &BlsSkValue,
  flag: BlsSchemeKind,
) -> bool {
  vvec.is_some_and(|vvec| verify_vector(&vvec.iter().collect::<Vec<_>>(), flag) && verify_share(for_id, vvec, share))
}

/// `CBLSWorker::VerifyContributionShares` (`bls_worker.cpp:686-719`,
/// `ContributionVerifier` `:388-588`): one answer per contribution.
///
/// All `false` when [`verify_verification_vectors`] fails. Otherwise, when
/// `aggregated`, each batch of [`CONTRIBUTION_VERIFY_BATCH_SIZE`] is checked
/// as the sum of its vectors against the sum of its shares; a batch whose
/// vectors are empty is all `false`, and a batch that fails is checked one
/// by one. Without `aggregated`, every contribution is checked alone.
///
/// Callers pass valid shares: this function answers all `false` for a
/// batch holding an invalid one, and for `vvecs` and `shares` of different
/// lengths.
pub fn verify_contribution_shares(
  for_id: &[u8; 32],
  vvecs: &[Option<&[BlsPkValue]>],
  shares: &[&BlsSkValue],
  aggregated: bool,
  flag: BlsSchemeKind,
) -> Vec<bool> {
  if vvecs.len() != shares.len() || !verify_verification_vectors(vvecs, flag) {
    return vec![false; vvecs.len()];
  }
  let Some(vvecs) = vvecs.iter().copied().collect::<Option<Vec<&[BlsPkValue]>>>() else {
    return vec![false; vvecs.len()];
  };
  let one_by_one = |vvecs: &[&[BlsPkValue]], shares: &[&BlsSkValue]| -> Vec<bool> {
    vvecs
      .iter()
      .zip(shares)
      .map(|(vvec, share)| verify_share(for_id, vvec, share))
      .collect()
  };
  if !aggregated {
    return one_by_one(&vvecs, shares);
  }
  let mut results = Vec::with_capacity(vvecs.len());
  for (vvecs, shares) in vvecs
    .chunks(CONTRIBUTION_VERIFY_BATCH_SIZE)
    .zip(shares.chunks(CONTRIBUTION_VERIFY_BATCH_SIZE))
  {
    let vvec = sum_vectors(vvecs);
    let share = sync_aggregate(shares, aggregate_secret_keys_insecure_pair).unwrap_or_else(BlsSkValue::invalid);
    if vvec.is_empty() || !share.is_valid() {
      results.extend(core::iter::repeat_n(false, vvecs.len()));
    } else if verify_share(for_id, &vvec, &share) {
      results.extend(core::iter::repeat_n(true, vvecs.len()));
    } else {
      results.extend(one_by_one(vvecs, shares));
    }
  }
  results
}

/// `CBLSWorker::GenerateContributions` (`bls_worker.cpp:78-118`): `t`
/// fresh coefficients, their public keys as the verification vector, and
/// each id's secret share; `None` when a share fails, as it does for every
/// id when `t` is below 2.
pub fn generate_contributions(
  t: usize,
  ids: &[[u8; 32]],
  rng: &mut impl CryptoRng,
) -> Option<(Vec<BlsPkValue>, Vec<BlsSkValue>)> {
  let svec: Vec<BlsSkValue> = (0..t).map(|_| make_new_key(rng)).collect();
  let vvec = svec.iter().map(public_key).collect();
  let svec: Vec<&BlsSkValue> = svec.iter().collect();
  let mut shares = Vec::with_capacity(ids.len());
  for id in ids {
    let mut share = BlsSkValue::invalid();
    if !secret_key_share(&mut share, &svec, id) {
      return None;
    }
    shares.push(share);
  }
  Some((vvec, shares))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use getrandom::SysRng;
  use rand_core::UnwrapErr;
  use rstest::rstest;

  fn ids(n: u8) -> Vec<[u8; 32]> {
    (1..=n).map(|i| [i; 32]).collect()
  }

  /// A DKG of `n` dealers with threshold `t`: each dealer's vector and the
  /// shares it sends to every member.
  fn dkg(n: u8, t: usize) -> Vec<(Vec<BlsPkValue>, Vec<BlsSkValue>)> {
    let mut rng = UnwrapErr(SysRng);
    (0..n)
      .map(|_| generate_contributions(t, &ids(n), &mut rng).unwrap())
      .collect()
  }

  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn contributions_verify(#[case] flag: BlsSchemeKind) {
    let dealers = dkg(10, 3);
    let member = 4;
    let vvecs: Vec<Option<&[BlsPkValue]>> = dealers.iter().map(|(v, _)| Some(v.as_slice())).collect();
    let mut shares: Vec<BlsSkValue> = dealers.iter().map(|(_, s)| s[member].clone()).collect();
    let id = ids(10)[member];
    for aggregated in [false, true] {
      let refs: Vec<&BlsSkValue> = shares.iter().collect();
      assert_eq!(
        verify_contribution_shares(&id, &vvecs, &refs, aggregated, flag),
        vec![true; 10]
      );
    }
    for (vvec, share) in vvecs.iter().zip(&shares) {
      assert!(verify_contribution_share(&id, *vvec, share, flag));
    }
    // A wrong share fails alone, in its batch's one-by-one fallback.
    shares[9] = shares[8].clone();
    let refs: Vec<&BlsSkValue> = shares.iter().collect();
    let mut want = vec![true; 10];
    want[9] = false;
    for aggregated in [false, true] {
      assert_eq!(verify_contribution_shares(&id, &vvecs, &refs, aggregated, flag), want);
    }
    // A missing vector fails them all.
    let mut missing = vvecs.clone();
    missing[3] = None;
    assert_eq!(
      verify_contribution_shares(&id, &missing, &refs, true, flag),
      vec![false; 10]
    );
    assert!(!verify_contribution_share(&id, None, &shares[0], flag));
    // Unequal spans fail them all.
    for aggregated in [false, true] {
      assert_eq!(
        verify_contribution_shares(&id, &vvecs, &refs[..9], aggregated, flag),
        vec![false; 10]
      );
    }
    assert!(verify_contribution_shares(&id, &[], &[], true, flag).is_empty());
  }

  /// An invalid share makes its batch's sum invalid, so the whole batch is
  /// `false`; other batches are checked as usual.
  #[test]
  fn invalid_share_fails_its_batch() {
    let flag = BlsSchemeKind::Basic;
    let dealers = dkg(10, 2);
    let vvecs: Vec<Option<&[BlsPkValue]>> = dealers.iter().map(|(v, _)| Some(v.as_slice())).collect();
    let mut shares: Vec<BlsSkValue> = dealers.iter().map(|(_, s)| s[0].clone()).collect();
    shares[1] = BlsSkValue::invalid();
    let refs: Vec<&BlsSkValue> = shares.iter().collect();
    let got = verify_contribution_shares(&ids(10)[0], &vvecs, &refs, true, flag);
    assert_eq!(got, [vec![false; 8], vec![true; 2]].concat());
  }

  /// The quorum vector is the dealers' element-wise sum; its key share for
  /// a member is the public key of the member's summed shares.
  #[test]
  fn quorum_vector_and_key_shares() {
    let flag = BlsSchemeKind::Basic;
    let dealers = dkg(5, 3);
    let vvecs: Vec<Option<&[BlsPkValue]>> = dealers.iter().map(|(v, _)| Some(v.as_slice())).collect();
    let quorum = build_quorum_verification_vector(&vvecs, flag).unwrap();
    assert_eq!(quorum.len(), 3);
    for (m, id) in ids(5).iter().enumerate() {
      let shares: Vec<&BlsSkValue> = dealers.iter().map(|(_, s)| &s[m]).collect();
      let sk = aggregate_secret_keys(&shares, flag);
      assert!(build_pub_key_share(&quorum, id).core_eq(&public_key(&sk)));
    }
    assert!(build_quorum_verification_vector(&[], flag).is_none());
    let mut short = vvecs.clone();
    short[2] = Some(&dealers[2].0[..2]);
    assert!(build_quorum_verification_vector(&short, flag).is_none());
  }

  /// The helper refuses invalid and repeated objects before adding.
  #[test]
  fn aggregates_refuse_invalid_and_repeated_objects() {
    let flag = BlsSchemeKind::Basic;
    let dealers = dkg(3, 2);
    let pks: Vec<&BlsPkValue> = dealers.iter().map(|(v, _)| &v[0]).collect();
    assert!(aggregate_public_keys(&pks, flag).is_valid());
    assert!(!aggregate_public_keys(&[pks[0], pks[1], pks[0]], flag).is_valid());
    assert!(!aggregate_public_keys(&[pks[0], &BlsPkValue::invalid()], flag).is_valid());
    assert!(!aggregate_public_keys(&[], flag).is_valid());
    assert!(!verify_verification_vectors(
      &[Some(dealers[0].0.as_slice()), Some(dealers[0].0.as_slice())],
      flag
    ));
    let sigs: [&BlsSigValue; 0] = [];
    assert!(!aggregate_signatures(&sigs, flag).is_valid());
  }

  /// A vector repeating an object is refused before the share is checked,
  /// though the share matches it (`VerifyVerificationVector`).
  #[test]
  fn a_repeated_vector_object_fails_its_share() {
    let flag = BlsSchemeKind::Basic;
    let k = dkg(1, 2)[0].1[0].clone();
    let vvec = [public_key(&k), public_key(&k)];
    let id = ids(1)[0];
    let mut share = BlsSkValue::invalid();
    assert!(secret_key_share(&mut share, &[&k, &k], &id));
    assert!(verify_share(&id, &vvec, &share));
    assert!(!verify_contribution_share(&id, Some(&vvec), &share, flag));
  }

  #[test]
  fn a_single_coefficient_gives_no_contribution() {
    let mut rng = UnwrapErr(SysRng);
    assert!(generate_contributions(1, &ids(3), &mut rng).is_none());
    assert!(generate_contributions(1, &[], &mut rng).is_some());
  }
}
