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
  aggregate_public_keys_insecure, aggregate_public_keys_insecure_pair, aggregate_secret_keys_insecure_pair,
  aggregate_signatures_insecure_pair, make_batch_verification_weight, make_new_key, mul_public_key_insecure,
  public_key, public_key_share, secret_key_share, BlsPkValue, BlsSigValue, BlsSkValue,
};
use crate::bls::{BlsSchemeKind, BlsValue, BlsWire};
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
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

/// `CBLSWorker::AsyncVerifyContributionShare` (`bls_worker.cpp:752-776`):
/// `false` for a missing vector or one [`verify_vector`] refuses.
pub fn verify_contribution_share(
  for_id: &[u8; 32],
  vvec: Option<&[BlsPkValue]>,
  share: &BlsSkValue,
  flag: BlsSchemeKind,
) -> bool {
  vvec.is_some_and(|vvec| verify_vector(&vvec.iter().collect::<Vec<_>>(), flag) && verify_share(for_id, vvec, share))
}

/// `ContributionVerifier::VerifyWeightedBatch` (`bls_worker.cpp:497-540`):
/// each share's public key and each coefficient of its vector are
/// multiplied by one 8-byte weight from `rng`, and the vectors are summed
/// element-wise. The batch passes when the sum's key share for `for_id`
/// equals the sum of the weighted keys.
///
/// `false` for an empty vector, an invalid share, a vector of another
/// length than the first, or an invalid coefficient or partial sum.
fn verify_weighted_batch(
  for_id: &[u8; 32],
  vvecs: &[&[BlsPkValue]],
  shares: &[&BlsSkValue],
  rng: &mut impl CryptoRng,
) -> bool {
  let mut sum: Vec<BlsPkValue> = Vec::new();
  let mut pks = Vec::with_capacity(shares.len());
  for (vvec, share) in vvecs.iter().zip(shares) {
    if vvec.is_empty() || !share.is_valid() || (!sum.is_empty() && vvec.len() != sum.len()) {
      return false;
    }
    let weight = make_batch_verification_weight::<8>(rng);
    pks.push(mul_public_key_insecure(&public_key(share), &weight));
    let first = sum.is_empty();
    for (j, coefficient) in vvec.iter().enumerate() {
      if !coefficient.is_valid() {
        return false;
      }
      let coefficient = mul_public_key_insecure(coefficient, &weight);
      if first {
        sum.push(coefficient);
      } else {
        sum[j] = aggregate_public_keys_insecure_pair(&sum[j], &coefficient);
      }
      if !sum[j].is_valid() {
        return false;
      }
    }
  }
  let mut expected = BlsPkValue::invalid();
  public_key_share(&mut expected, &sum.iter().collect::<Vec<_>>(), for_id)
    && expected.core_eq(&aggregate_public_keys_insecure(&pks.iter().collect::<Vec<_>>()))
}

/// [`verify_contribution_shares`]'s answer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ContributionVerdicts {
  /// One answer per contribution.
  pub verdicts: Vec<bool>,
  /// Whether [`verify_verification_vectors`] refused the vectors, so each
  /// contribution was checked alone. Core logs this under `LLMQ_DKG`.
  pub individually: bool,
}

/// `CBLSWorker::VerifyContributionShares` (`bls_worker.cpp:688-736`,
/// `ContributionVerifier` `:388-588`): one answer per contribution.
///
/// When [`verify_verification_vectors`] fails, each contribution is checked
/// alone by [`verify_contribution_share`]. Otherwise, when `aggregated`,
/// each batch of [`CONTRIBUTION_VERIFY_BATCH_SIZE`] is checked by weighted
/// sums with weights from `rng`, and a batch that fails is checked one by
/// one. Without `aggregated`, every contribution is checked alone.
///
/// The weighting is sound only for points in the subgroup, so callers that
/// may hold vectors decoded under the legacy scheme pass `aggregated =
/// false`, as Core's header states. `vvecs` and `shares` of different
/// lengths give all `false`, which Core does not check.
pub fn verify_contribution_shares(
  for_id: &[u8; 32],
  vvecs: &[Option<&[BlsPkValue]>],
  shares: &[&BlsSkValue],
  aggregated: bool,
  flag: BlsSchemeKind,
  rng: &mut impl CryptoRng,
) -> ContributionVerdicts {
  let verdicts = |verdicts: Vec<bool>| ContributionVerdicts {
    verdicts,
    individually: false,
  };
  if vvecs.len() != shares.len() {
    return verdicts(vec![false; vvecs.len()]);
  }
  if !verify_verification_vectors(vvecs, flag) {
    return ContributionVerdicts {
      verdicts: vvecs
        .iter()
        .zip(shares)
        .map(|(vvec, share)| verify_contribution_share(for_id, *vvec, share, flag))
        .collect(),
      individually: true,
    };
  }
  let vvecs: Vec<&[BlsPkValue]> = vvecs.iter().copied().flatten().collect();
  let one_by_one = |vvecs: &[&[BlsPkValue]], shares: &[&BlsSkValue]| -> Vec<bool> {
    vvecs
      .iter()
      .zip(shares)
      .map(|(vvec, share)| verify_share(for_id, vvec, share))
      .collect()
  };
  if !aggregated {
    return verdicts(one_by_one(&vvecs, shares));
  }
  let mut results = Vec::with_capacity(vvecs.len());
  for (vvecs, shares) in vvecs
    .chunks(CONTRIBUTION_VERIFY_BATCH_SIZE)
    .zip(shares.chunks(CONTRIBUTION_VERIFY_BATCH_SIZE))
  {
    if verify_weighted_batch(for_id, vvecs, shares, rng) {
      results.extend(core::iter::repeat_n(true, vvecs.len()));
    } else {
      results.extend(one_by_one(vvecs, shares));
    }
  }
  verdicts(results)
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
  use super::super::tests::TestRng;
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
        verify_contribution_shares(&id, &vvecs, &refs, aggregated, flag, &mut TestRng(1)).verdicts,
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
      assert_eq!(
        verify_contribution_shares(&id, &vvecs, &refs, aggregated, flag, &mut TestRng(1)).verdicts,
        want
      );
    }
    // A missing vector fails alone.
    let mut missing = vvecs.clone();
    missing[3] = None;
    want[3] = false;
    for aggregated in [false, true] {
      assert_eq!(
        verify_contribution_shares(&id, &missing, &refs, aggregated, flag, &mut TestRng(1)).verdicts,
        want
      );
    }
    assert!(!verify_contribution_share(&id, None, &shares[0], flag));
    // Unequal spans fail them all.
    for aggregated in [false, true] {
      assert_eq!(
        verify_contribution_shares(&id, &vvecs, &refs[..9], aggregated, flag, &mut TestRng(1)).verdicts,
        vec![false; 10]
      );
    }
    let empty = verify_contribution_shares(&id, &[], &[], true, flag, &mut TestRng(1));
    assert!(empty.verdicts.is_empty() && !empty.individually);
  }

  /// `VerifyWeightedBatch` refuses an empty vector, an invalid share, a
  /// vector of another length and an invalid coefficient.
  #[test]
  fn weighted_batch_refusals() {
    let dealers = dkg(3, 2);
    let id = ids(3)[0];
    let vvecs: Vec<&[BlsPkValue]> = dealers.iter().map(|(v, _)| v.as_slice()).collect();
    let shares: Vec<&BlsSkValue> = dealers.iter().map(|(_, s)| &s[0]).collect();
    let mut rng = TestRng(2);
    assert!(verify_weighted_batch(&id, &vvecs, &shares, &mut rng));
    assert!(verify_weighted_batch(&id, &vvecs[..1], &shares[..1], &mut rng));
    let invalid = BlsSkValue::invalid();
    assert!(!verify_weighted_batch(
      &id,
      &vvecs,
      &[shares[0], &invalid, shares[2]],
      &mut rng
    ));
    assert!(!verify_weighted_batch(
      &id,
      &[vvecs[0], &vvecs[1][..1], vvecs[2]],
      &shares,
      &mut rng
    ));
    assert!(!verify_weighted_batch(&id, &[&[], &[], &[]], &shares, &mut rng));
    let mut bad = dealers[1].0.clone();
    bad[1] = BlsPkValue::invalid();
    assert!(!verify_weighted_batch(
      &id,
      &[vvecs[0], &bad, vvecs[2]],
      &shares,
      &mut rng
    ));
  }

  /// Ids 1 to `n` as Core's tests write them, `WriteLE64` into a `uint256`.
  fn le64_ids(n: u64) -> Vec<[u8; 32]> {
    (1..=n)
      .map(|i| {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&i.to_le_bytes());
        id
      })
      .collect()
  }

  /// Core's `FuncVerifyContributionSharesDuplicateCoefficient`
  /// (`test/bls_tests.cpp`, rc.5 #7965): dealer 0 takes dealer 1's first
  /// coefficient and keeps its share, so dealer 0 alone fails.
  #[rstest]
  fn shared_coefficient_fails_only_its_dealer(
    #[values(BlsSchemeKind::Legacy, BlsSchemeKind::Basic)] flag: BlsSchemeKind,
    #[values(false, true)] aggregated: bool,
  ) {
    let ids = le64_ids(4);
    let mut rng = UnwrapErr(SysRng);
    let mut dealers: Vec<(Vec<BlsPkValue>, Vec<BlsSkValue>)> = (0..3)
      .map(|_| generate_contributions(2, &ids, &mut rng).unwrap())
      .collect();
    let shares: Vec<BlsSkValue> = dealers.iter().map(|(_, s)| s[0].clone()).collect();
    let refs: Vec<&BlsSkValue> = shares.iter().collect();
    let vvecs: Vec<Option<&[BlsPkValue]>> = dealers.iter().map(|(v, _)| Some(v.as_slice())).collect();
    assert_eq!(
      verify_contribution_shares(&ids[0], &vvecs, &refs, aggregated, flag, &mut TestRng(1)),
      ContributionVerdicts {
        verdicts: vec![true; 3],
        individually: false,
      }
    );
    dealers[0].0[0] = dealers[1].0[0].clone();
    let vvecs: Vec<Option<&[BlsPkValue]>> = dealers.iter().map(|(v, _)| Some(v.as_slice())).collect();
    assert_eq!(
      verify_contribution_shares(&ids[0], &vvecs, &refs, aggregated, flag, &mut TestRng(1)),
      ContributionVerdicts {
        verdicts: vec![false, true, true],
        individually: true,
      }
    );
  }

  /// Core's `FuncVerifyContributionSharesHonest` (`test/bls_tests.cpp`,
  /// v24.0.0 #8016): ten dealers of threshold 6 over two batches. A wrong
  /// share fails alone. Two shares swapped within a batch fail both, and an
  /// invalid share fails alone.
  #[rstest]
  #[case::legacy(BlsSchemeKind::Legacy)]
  #[case::basic(BlsSchemeKind::Basic)]
  fn cores_contribution_shares_test(#[case] flag: BlsSchemeKind) {
    let n = CONTRIBUTION_VERIFY_BATCH_SIZE + 2;
    let ids = le64_ids(n as u64);
    let mut rng = UnwrapErr(SysRng);
    let dealers: Vec<(Vec<BlsPkValue>, Vec<BlsSkValue>)> = (0..n)
      .map(|_| generate_contributions(6, &ids, &mut rng).unwrap())
      .collect();
    let vvecs: Vec<Option<&[BlsPkValue]>> = dealers.iter().map(|(v, _)| Some(v.as_slice())).collect();
    let shares: Vec<BlsSkValue> = dealers.iter().map(|(_, s)| s[0].clone()).collect();
    let check = |shares: &[BlsSkValue], aggregated: bool, bad: &[usize]| {
      let refs: Vec<&BlsSkValue> = shares.iter().collect();
      let want: Vec<bool> = (0..n).map(|i| !bad.contains(&i)).collect();
      assert_eq!(
        verify_contribution_shares(&ids[0], &vvecs, &refs, aggregated, flag, &mut TestRng(1)).verdicts,
        want,
        "aggregated {aggregated} bad {bad:?}"
      );
    };
    let mut corrupted = shares.clone();
    corrupted[3] = make_new_key(&mut rng);
    for aggregated in [true, false] {
      check(&shares, aggregated, &[]);
      check(&corrupted, aggregated, &[3]);
    }
    let mut swapped = shares.clone();
    swapped.swap(1, 2);
    let mut missing = shares.clone();
    missing[5] = BlsSkValue::invalid();
    check(&swapped, true, &[1, 2]);
    check(&missing, true, &[5]);
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
