//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for BLS schemes.

use crate::common::bls::{sequential_ids, test_ikm, test_msg};

use dash_pkc::bls::core::{verify_insecure, BlsPkValue, BlsSigValue};
use dash_pkc::bls::{
  BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSchemeKind, BlsSecretKey, BlsSigShare, BlsSignature, BlsValue,
};
use divan::{counter::ItemsCount, Bencher};
use getrandom::SysRng;
use rand_core::UnwrapErr;

/// Single signature creation.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn sign<S: BlsScheme>(bencher: Bencher) {
  let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(1)).unwrap();
  bencher
    .counter(ItemsCount::new(1u32))
    .bench(|| sk.sign(S::msg_ref(&test_msg(42))));
}

/// Single signature verification.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn verify<S: BlsScheme>(bencher: Bencher) {
  let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(2)).unwrap();
  let msg = test_msg(99);
  let sig = sk.sign(S::msg_ref(&msg));
  let pk = sk.public_key();
  bencher
    .counter(ItemsCount::new(1u32))
    .bench(|| pk.verify(S::msg_ref(&msg), &sig));
}

/// Single signature verification as Core makes it, on the calling thread
/// alone; [`verify`] is the pooled one.
#[divan::bench(args = [BlsSchemeKind::Legacy, BlsSchemeKind::Basic])]
fn verify_core(bencher: Bencher, kind: BlsSchemeKind) {
  let (msg, sig, pk) = match kind {
    BlsSchemeKind::Legacy => core_operands::<BlsScChia>(kind),
    BlsSchemeKind::Basic => core_operands::<BlsScIetf>(kind),
  };
  bencher
    .counter(ItemsCount::new(1u32))
    .bench(|| verify_insecure(&sig, &pk, &msg, kind));
}

fn core_operands<S: BlsScheme>(kind: BlsSchemeKind) -> ([u8; 32], BlsSigValue, BlsPkValue) {
  let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(2)).unwrap();
  let msg = test_msg(99);
  let sig = sk.sign(S::msg_ref(&msg)).to_bytes();
  let pk = sk.public_key().to_bytes();
  let sig = BlsValue::from_canonical(&sig, kind).unwrap();
  let pk = BlsValue::from_canonical(&pk, kind).unwrap();
  (msg, sig, pk)
}

/// Public key aggregation at various quorum sizes.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 5, 25, 50, 100])]
fn aggregate_pk_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let pks: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap().public_key())
    .collect();
  let pk_refs: Vec<_> = pks.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| BlsPublicKey::<S>::aggregate(&pk_refs));
}

/// Signature aggregation at various batch sizes.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 10, 100])]
fn aggregate_sig_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap())
    .collect();
  let sigs: Vec<_> = keys
    .iter()
    .enumerate()
    .map(|(i, key)| key.sign(S::msg_ref(&test_msg(i))))
    .collect();
  let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| BlsSignature::<S>::aggregate(&sig_refs));
}

/// N individual verifications in a loop.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [100, 1000])]
fn verify_n_individual<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(test_msg).collect();
  let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
  let sigs: Vec<_> = keys
    .iter()
    .zip(&msgs)
    .map(|(key, msg)| key.sign(S::msg_ref(msg)))
    .collect();

  bencher.counter(ItemsCount::new(n)).bench(|| {
    for i in 0..n {
      let _ = pks[i].verify(S::msg_ref(&msgs[i]), &sigs[i]);
    }
  });
}

/// Fast aggregate verification over a shared message.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [10, 100, 1000])]
fn fast_verify_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap())
    .collect();
  let msg = test_msg(42);
  let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
  let sigs: Vec<_> = keys.iter().map(|key| key.sign(S::msg_ref(&msg))).collect();
  let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
  let aggregate = BlsSignature::<S>::aggregate(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();

  bencher
    .counter(ItemsCount::new(n))
    .bench(|| aggregate.fast_verify_aggregates(S::msg_ref(&msg), &pk_refs));
}

/// Public key serialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn ser_pk<S: BlsScheme>(bencher: Bencher) {
  let pk = BlsSecretKey::<S>::from_ikm(&test_ikm(1)).unwrap().public_key();
  bencher.bench(|| pk.to_bytes());
}

/// Public key deserialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn deser_pk<S: BlsScheme>(bencher: Bencher) {
  let bytes = BlsSecretKey::<S>::from_ikm(&test_ikm(1))
    .unwrap()
    .public_key()
    .to_bytes();
  bencher.bench(|| BlsPublicKey::<S>::from_bytes(&bytes));
}

/// Signature serialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn ser_sig<S: BlsScheme>(bencher: Bencher) {
  let sig = BlsSecretKey::<S>::from_ikm(&test_ikm(1))
    .unwrap()
    .sign(S::msg_ref(&test_msg(0)));
  bencher.bench(|| sig.to_bytes());
}

/// Signature deserialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn deser_sig<S: BlsScheme>(bencher: Bencher) {
  let bytes = BlsSecretKey::<S>::from_ikm(&test_ikm(1))
    .unwrap()
    .sign(S::msg_ref(&test_msg(0)))
    .to_bytes();
  bencher.bench(|| BlsSignature::<S>::from_bytes(&bytes));
}

/// Threshold secret key splitting at various quorum sizes.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [5, 10, 50])]
fn split_threshold<S: BlsScheme>(bencher: Bencher, n: usize) {
  let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(1)).unwrap();
  let threshold = n.div_ceil(2);
  let ids = sequential_ids(n);
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| sk.split(threshold, &ids, &mut UnwrapErr(SysRng)));
}

/// Threshold signature recovery via Lagrange interpolation.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [3, 5, 10])]
fn recover_threshold<S: BlsScheme>(bencher: Bencher, threshold: usize) {
  let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(1)).unwrap();
  let ids = sequential_ids(threshold * 2);
  let shares = sk.split(threshold, &ids, &mut UnwrapErr(SysRng)).unwrap();
  let msg = test_msg(42);
  let sig_shares: Vec<_> = shares.iter().map(|share| share.sign(S::msg_ref(&msg))).collect();
  let subset: Vec<&BlsSigShare<S>> = sig_shares.iter().take(threshold).collect();
  bencher
    .counter(ItemsCount::new(threshold))
    .bench(|| BlsSignature::<S>::recover_shares(&subset));
}

/// Aggregate signatures over distinct messages, then verify.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [10, 100, 1000])]
fn verify_aggregated_block<S: BlsScheme>(bencher: Bencher, n: usize)
where
  S::Msg: Sync,
{
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(test_msg).collect();
  let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
  let sigs: Vec<_> = keys
    .iter()
    .zip(&msgs)
    .map(|(key, msg)| key.sign(S::msg_ref(msg)))
    .collect();
  let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
  let aggregate = BlsSignature::<S>::aggregate(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();
  let msg_refs: Vec<&S::Msg> = msgs.iter().map(|msg| S::msg_ref(msg)).collect();

  bencher
    .counter(ItemsCount::new(n))
    .bench(|| aggregate.verify_aggregates(&msg_refs, &pk_refs));
}

/// Public-key-weighted aggregation, one scalar multiplication per signature on
/// top of the plain sum.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 10, 100])]
fn secure_aggregate_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap())
    .collect();
  let msg = test_msg(42);
  let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
  let sigs: Vec<_> = keys.iter().map(|key| key.sign(S::msg_ref(&msg))).collect();
  let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
  let pk_refs: Vec<_> = pks.iter().collect();

  bencher
    .counter(ItemsCount::new(n))
    .bench(|| BlsSignature::<S>::secure_aggregate(&sig_refs, &pk_refs));
}

/// Evaluating the master secret polynomial at a participant id, over a master
/// key of `n` coefficients.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 5, 10])]
fn derive_share_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let master: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap())
    .collect();
  let master_refs: Vec<&BlsSecretKey<S>> = master.iter().collect();
  let id = sequential_ids(1)[0];

  bencher
    .counter(ItemsCount::new(n))
    .bench(|| BlsSecretKey::<S>::derive_share(&master_refs, &id));
}

/// Sealing one blob to one recipient, over a plaintext of `n` blocks.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [1, 2, 16])]
fn ies_encrypt_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let pk = BlsSecretKey::<S>::from_ikm(&test_ikm(1)).unwrap().public_key();
  let plaintext = vec![0x42u8; n * 16];
  let mut rng = UnwrapErr(SysRng);

  bencher
    .counter(ItemsCount::new(n))
    .bench_local(|| pk.ies_encrypt(&plaintext, &mut rng));
}

/// Opening one blob, paying for a DH exchange.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [1, 2, 16])]
fn ies_decrypt_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let sk = BlsSecretKey::<S>::from_ikm(&test_ikm(1)).unwrap();
  let plaintext = vec![0x42u8; n * 16];
  let blob = sk.public_key().ies_encrypt(&plaintext, &mut UnwrapErr(SysRng)).unwrap();

  bencher.counter(ItemsCount::new(n)).bench(|| sk.ies_decrypt(&blob, 0));
}

/// Sealing one 32-byte share to each of `n` recipients.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 10, 100])]
fn ies_encrypt_multi_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let pks: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::from_ikm(&test_ikm(i)).unwrap().public_key())
    .collect();
  let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
  let plaintexts = vec![[0x42u8; 32]; n];
  let pt_refs: Vec<&[u8]> = plaintexts.iter().map(|p| p.as_slice()).collect();
  let mut rng = UnwrapErr(SysRng);

  bencher
    .counter(ItemsCount::new(n))
    .bench_local(|| BlsPublicKey::<S>::ies_encrypt_multi(&pk_refs, &pt_refs, &mut rng));
}

/// IETF-only BLS operations.
mod ietf {
  use super::*;

  /// Proof of possession creation.
  #[divan::bench]
  fn prove_pop(bencher: Bencher) {
    let sk = BlsSecretKey::<BlsScIetf>::from_ikm(&test_ikm(1)).unwrap();
    bencher.bench(|| sk.prove_possession());
  }

  /// Proof of possession verification.
  #[divan::bench]
  fn verify_pop(bencher: Bencher) {
    let sk = BlsSecretKey::<BlsScIetf>::from_ikm(&test_ikm(1)).unwrap();
    let pop = sk.prove_possession();
    let pk = sk.public_key();
    bencher.bench(|| pk.verify_possession(&pop));
  }
}
