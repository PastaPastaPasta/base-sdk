//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's `CBLSBatchVerifier` (`bls/bls_batchverifier.h`).

use super::{
  aggregate_public_keys_insecure, aggregate_signatures_insecure, verify_insecure, verify_insecure_aggregated,
  BlsPkValue, BlsSigValue, BlsVerdict,
};
use crate::bls::BlsSchemeKind;
use crate::prelude::*;

use alloc::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// A pushed message.
#[derive(Clone, Debug)]
struct Message {
  hash: [u8; 32],
  sig: BlsSigValue,
  pk: BlsPkValue,
}

/// `CBLSBatchVerifier<SourceId, MessageId>`: signatures checked as one
/// aggregate, then per source and per message when the aggregate fails.
///
/// Message hashes are `uint256`s in their stored order, which Core's maps
/// order as these arrays order. Core reads the process-wide scheme flag at
/// verification; the verifier takes it at construction, as Core's callers
/// build one per batch.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct BlsBatchVerifier<S: Ord + Clone, M: Ord + Clone> {
  secure: bool,
  per_message_fallback: bool,
  sub_batch_size: usize,
  flag: BlsSchemeKind,
  messages: BTreeMap<M, Message>,
  by_source: BTreeMap<S, Vec<M>>,
  bad_sources: BTreeSet<S>,
  bad_messages: BTreeSet<M>,
  unsupported: bool,
}

impl<S: Ord + Clone, M: Ord + Clone> BlsBatchVerifier<S, M> {
  /// `CBLSBatchVerifier(secure, perMessageFallback, subBatchSize)`; a
  /// `sub_batch_size` of 0 never verifies on push.
  pub fn new(secure: bool, per_message_fallback: bool, sub_batch_size: usize, flag: BlsSchemeKind) -> Self {
    Self {
      secure,
      per_message_fallback,
      sub_batch_size,
      flag,
      messages: BTreeMap::new(),
      by_source: BTreeMap::new(),
      bad_sources: BTreeSet::new(),
      bad_messages: BTreeSet::new(),
      unsupported: false,
    }
  }

  /// `PushMessage`. A repeated message id keeps its first message, and the
  /// source still lists it. When the sub-batch size is reached, the
  /// messages are verified and cleared.
  ///
  /// Core asserts that both objects are valid; here an invalid one is not
  /// pushed and the call returns `false`.
  pub fn push_message(&mut self, source: S, id: M, hash: [u8; 32], sig: &BlsSigValue, pk: &BlsPkValue) -> bool {
    if !sig.is_valid() || !pk.is_valid() {
      return false;
    }
    self.messages.entry(id.clone()).or_insert_with(|| Message {
      hash,
      sig: sig.clone(),
      pk: pk.clone(),
    });
    self.by_source.entry(source).or_default().push(id);
    if self.sub_batch_size != 0 && self.messages.len() >= self.sub_batch_size {
      let _ = self.verify();
      self.clear_messages();
    }
    true
  }

  /// `ClearMessages`: drops the messages, keeping the bad sets.
  pub fn clear_messages(&mut self) {
    self.messages.clear();
    self.by_source.clear();
  }

  /// `GetUniqueSourceCount`.
  pub fn unique_source_count(&self) -> usize {
    self.by_source.len()
  }

  /// The sources found bad so far, Core's `badSources`.
  pub fn bad_sources(&self) -> &BTreeSet<S> {
    &self.bad_sources
  }

  /// The messages found bad so far, Core's `badMessages`; filled only with
  /// the per-message fallback.
  pub fn bad_messages(&self) -> &BTreeSet<M> {
    &self.bad_messages
  }

  /// Whether a verification so far met an operand Core checks with relic's
  /// arithmetic off the subgroup ([`BlsVerdict::Unsupported`]). The bad
  /// sets are then unspecified.
  pub fn unsupported(&self) -> bool {
    self.unsupported
  }

  /// `Verify`: the whole batch, then, if it fails, each source in order,
  /// re-batched unless it is the only one, and each bad source's messages
  /// one by one with the per-message fallback. The messages are kept.
  ///
  /// Returns whether the whole batch passed, or [`BlsVerdict::Unsupported`]
  /// when any check this call made was unsupported.
  pub fn verify(&mut self) -> BlsVerdict {
    let mut by_hash: BTreeMap<[u8; 32], Vec<&M>> = BTreeMap::new();
    for (id, msg) in &self.messages {
      by_hash.entry(msg.hash).or_default().push(id);
    }
    let whole = self.verify_batch(by_hash);
    let mut unsupported = whole == BlsVerdict::Unsupported;
    if !whole.is_valid() {
      let (sources, messages, fallback_unsupported) = self.fall_back();
      self.bad_sources.extend(sources);
      self.bad_messages.extend(messages);
      unsupported |= fallback_unsupported;
    }
    self.unsupported |= unsupported;
    if unsupported {
      BlsVerdict::Unsupported
    } else {
      whole
    }
  }

  /// `Verify`'s fallback: the bad sources and messages it finds, and
  /// whether any check it made was unsupported.
  fn fall_back(&self) -> (Vec<S>, Vec<M>, bool) {
    let mut bad_sources = Vec::new();
    let mut bad_messages: Vec<M> = Vec::new();
    let mut unsupported = false;
    for (source, ids) in &self.by_source {
      let mut valid = BlsVerdict::Invalid;
      if self.by_source.len() != 1 {
        let mut by_hash: BTreeMap<[u8; 32], Vec<&M>> = BTreeMap::new();
        for id in ids {
          by_hash.entry(self.messages[id].hash).or_default().push(id);
        }
        valid = self.verify_batch(by_hash);
        unsupported |= valid == BlsVerdict::Unsupported;
      }
      if valid.is_valid() {
        continue;
      }
      bad_sources.push(source.clone());
      if !self.per_message_fallback {
        continue;
      }
      if let [id] = ids.as_slice() {
        bad_messages.push(id.clone());
        continue;
      }
      for id in ids {
        if self.bad_messages.contains(id) || bad_messages.contains(id) {
          continue;
        }
        let msg = &self.messages[id];
        let verdict = verify_insecure(&msg.sig, &msg.pk, &msg.hash, self.flag);
        unsupported |= verdict == BlsVerdict::Unsupported;
        if !verdict.is_valid() {
          bad_messages.push(id.clone());
        }
      }
    }
    (bad_sources, bad_messages, unsupported)
  }

  fn verify_batch(&self, by_hash: BTreeMap<[u8; 32], Vec<&M>>) -> BlsVerdict {
    if self.secure {
      self.verify_batch_secure(by_hash)
    } else {
      self.verify_batch_insecure(&by_hash)
    }
  }

  /// `VerifyBatchInsecure`: the keys aggregated per hash, skipping message
  /// ids already taken, and every signature aggregated.
  fn verify_batch_insecure(&self, by_hash: &BTreeMap<[u8; 32], Vec<&M>>) -> BlsVerdict {
    let mut sigs = Vec::new();
    let mut hashes = Vec::new();
    let mut pks = Vec::new();
    let mut dups = BTreeSet::new();
    for (hash, ids) in by_hash {
      let mut keys = Vec::new();
      for id in ids {
        if !dups.insert(*id) {
          continue;
        }
        let msg = &self.messages[*id];
        sigs.push(&msg.sig);
        keys.push(&msg.pk);
      }
      let agg = aggregate_public_keys_insecure(&keys);
      if !agg.is_valid() {
        continue;
      }
      hashes.push(*hash);
      pks.push(agg);
    }
    if hashes.is_empty() {
      return BlsVerdict::Valid;
    }
    let sig = aggregate_signatures_insecure(&sigs);
    verify_insecure_aggregated(&sig, &pks.iter().collect::<Vec<_>>(), &hashes, self.flag)
  }

  /// `VerifyBatchSecure`: rounds taking the last message of each hash until
  /// none is left.
  fn verify_batch_secure(&self, mut by_hash: BTreeMap<[u8; 32], Vec<&M>>) -> BlsVerdict {
    while !by_hash.is_empty() {
      let mut sigs = Vec::new();
      let mut hashes = Vec::new();
      let mut pks = Vec::new();
      let mut dups = BTreeSet::new();
      by_hash.retain(|hash, ids| {
        if let Some(id) = ids.pop() {
          if dups.insert(id) {
            let msg = &self.messages[id];
            hashes.push(*hash);
            pks.push(&msg.pk);
            sigs.push(&msg.sig);
          }
        }
        !ids.is_empty()
      });
      let sig = aggregate_signatures_insecure(&sigs);
      let verdict = verify_insecure_aggregated(&sig, &pks, &hashes, self.flag);
      if !verdict.is_valid() {
        return verdict;
      }
    }
    BlsVerdict::Valid
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey};

  use rstest::rstest;

  /// A message of `test/bls_tests.cpp`'s `AddMessage`: a fresh key's
  /// signature of `uint256(hash)`, or another key's when invalid.
  struct Msg {
    source: u32,
    id: u32,
    hash: [u8; 32],
    sig: BlsSigValue,
    pk: BlsPkValue,
    valid: bool,
  }

  fn add<S: BlsScheme>(msgs: &mut Vec<Msg>, source: u32, id: u32, hash: u8, valid: bool, kind: BlsSchemeKind) {
    let mut h = [0u8; 32];
    h[0] = hash;
    let key = |seed: u32| {
      let mut ikm = [0u8; 32];
      ikm[..4].copy_from_slice(&seed.to_le_bytes());
      BlsSecretKey::<S>::from_ikm(&ikm).unwrap()
    };
    let sk = key(2 * id);
    let signer = if valid { key(2 * id) } else { key(2 * id + 1) };
    msgs.push(Msg {
      source,
      id,
      hash: h,
      sig: BlsSigValue::from_canonical(&signer.sign(S::msg_ref(&h)).to_bytes(), kind).unwrap(),
      pk: BlsPkValue::from_canonical(&sk.public_key().to_bytes(), kind).unwrap(),
      valid,
    });
  }

  /// `test/bls_tests.cpp`'s `Verify`: the bad sources are the invalid
  /// messages' sources, and the bad messages the invalid messages with the
  /// per-message fallback, none without.
  fn check(msgs: &[Msg], kind: BlsSchemeKind) {
    for (secure, per_message) in [(false, false), (true, false), (false, true), (true, true)] {
      let mut verifier = BlsBatchVerifier::new(secure, per_message, 0, kind);
      for m in msgs {
        assert!(verifier.push_message(m.source, m.id, m.hash, &m.sig, &m.pk));
      }
      let all_valid = msgs.iter().all(|m| m.valid);
      assert_eq!(verifier.verify().is_valid(), all_valid);
      let bad_sources: BTreeSet<u32> = msgs.iter().filter(|m| !m.valid).map(|m| m.source).collect();
      let bad_messages: BTreeSet<u32> = msgs.iter().filter(|m| !m.valid && per_message).map(|m| m.id).collect();
      assert_eq!(
        verifier.bad_sources(),
        &bad_sources,
        "secure {secure} per-message {per_message}"
      );
      assert_eq!(
        verifier.bad_messages(),
        &bad_messages,
        "secure {secure} per-message {per_message}"
      );
      assert!(!verifier.unsupported());
    }
  }

  /// Core's `FuncBatchVerifier` (`test/bls_tests.cpp:323-372`).
  fn func_batch_verifier<S: BlsScheme>(kind: BlsSchemeKind) {
    let mut msgs = Vec::new();
    for i in 1..=3 {
      add::<S>(&mut msgs, i, i, i as u8, true, kind);
    }
    check(&msgs, kind);
    for i in 4..=6 {
      add::<S>(&mut msgs, 4, i, i as u8, true, kind);
    }
    check(&msgs, kind);
    add::<S>(&mut msgs, 7, 7, 7, false, kind);
    check(&msgs, kind);
    add::<S>(&mut msgs, 8, 8, 7, true, kind);
    check(&msgs, kind);
    add::<S>(&mut msgs, 9, 9, 7, true, kind);
    check(&msgs, kind);

    msgs.clear();
    for (source, id) in [(1, 1), (1, 2), (1, 3), (2, 4), (2, 5), (2, 6)] {
      add::<S>(&mut msgs, source, id, 1, true, kind);
    }
    check(&msgs, kind);
    add::<S>(&mut msgs, 1, 7, 1, false, kind);
    check(&msgs, kind);
  }

  #[rstest]
  #[case::legacy(func_batch_verifier::<BlsScChia>, BlsSchemeKind::Legacy)]
  #[case::basic(func_batch_verifier::<BlsScIetf>, BlsSchemeKind::Basic)]
  fn cores_batch_verifier_test(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// A repeated message id keeps its first message; the source still lists
  /// it, so a bad source is found whose own message was never verified.
  #[test]
  fn repeated_id_keeps_the_first_message() {
    let kind = BlsSchemeKind::Basic;
    let mut msgs = Vec::new();
    add::<BlsScIetf>(&mut msgs, 1, 1, 1, true, kind);
    add::<BlsScIetf>(&mut msgs, 2, 2, 2, false, kind);
    let mut verifier = BlsBatchVerifier::new(false, true, 0, kind);
    verifier.push_message(1, 1u32, msgs[0].hash, &msgs[0].sig, &msgs[0].pk);
    verifier.push_message(2, 1u32, msgs[1].hash, &msgs[1].sig, &msgs[1].pk);
    assert_eq!(verifier.verify(), BlsVerdict::Valid);
    assert!(verifier.bad_sources().is_empty());
  }

  /// Invalid objects are not pushed (Core asserts), and a sub-batch
  /// verifies and clears on reaching its size, keeping the bad sets.
  #[test]
  fn push_refusals_and_sub_batches() {
    let kind = BlsSchemeKind::Basic;
    let mut msgs = Vec::new();
    add::<BlsScIetf>(&mut msgs, 1, 1, 1, false, kind);
    add::<BlsScIetf>(&mut msgs, 2, 2, 2, true, kind);
    let mut verifier = BlsBatchVerifier::new(false, true, 2, kind);
    assert!(!verifier.push_message(1, 1u32, msgs[0].hash, &BlsSigValue::invalid(), &msgs[0].pk));
    assert!(verifier.push_message(1, 1u32, msgs[0].hash, &msgs[0].sig, &msgs[0].pk));
    assert!(verifier.push_message(2, 2u32, msgs[1].hash, &msgs[1].sig, &msgs[1].pk));
    assert_eq!(verifier.unique_source_count(), 0);
    assert_eq!(verifier.bad_sources(), &BTreeSet::from([1]));
    assert_eq!(verifier.bad_messages(), &BTreeSet::from([1]));
  }
}
