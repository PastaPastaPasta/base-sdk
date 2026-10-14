//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the ecdsa (secp256k1) feature

use crate::common::ecdsa::{message_hash, ALICE_SK};

use dash_pkc::ecdsa::{Compression, EcdsaPublicKey, EcdsaSecretKey};

fn test_key() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&ALICE_SK, Compression::Compressed).unwrap()
}

#[divan::bench]
fn sign(bencher: divan::Bencher) {
  let sk = test_key();
  bencher.counter(divan::counter::ItemsCount::new(1u32)).bench(|| {
    let msg = message_hash(42);
    sk.sign_digest(&msg)
  });
}

#[divan::bench]
fn verify(bencher: divan::Bencher) {
  let sk = test_key();
  let msg = message_hash(99);
  let sig = sk.sign_digest(&msg);
  let pk = sk.public_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| pk.verify_digest(&msg, sig));
}

#[divan::bench]
fn sign_recoverable(bencher: divan::Bencher) {
  let sk = test_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| sk.sign_recoverable(&message_hash(7)));
}

#[divan::bench]
fn recover(bencher: divan::Bencher) {
  let sk = test_key();
  let msg = message_hash(55);
  let sig = sk.sign_recoverable(&msg);
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| EcdsaPublicKey::recover(&msg, &sig).unwrap());
}

#[divan::bench]
fn ser_pk(bencher: divan::Bencher) {
  let pk = test_key().public_key();
  bencher.bench(|| pk.to_compressed());
}

#[divan::bench]
fn deser_pk(bencher: divan::Bencher) {
  let bytes = test_key().public_key().to_compressed();
  bencher.bench(|| EcdsaPublicKey::from_bytes(&bytes).unwrap());
}
