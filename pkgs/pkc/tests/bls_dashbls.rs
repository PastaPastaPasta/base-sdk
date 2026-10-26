//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The fixed vectors in dashbls' `test.cpp` (Dash Core v24.0.0-rc.3), replayed
//! through the typed API and, for aggregation and recovery, `bls::core`.
//! `corpus/bls_dashbls.json5` holds them verbatim and `corpus/PROVENANCE.md`
//! says where from.

#![cfg(feature = "bls")]
#![expect(clippy::unwrap_used, reason = "test code")]

use bitcoin_hashes::sha256::Hash as Sha256;
use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
use dash_pkc::bls::core::{aggregate_signatures_insecure, recover_signature, BlsPkValue, BlsSigValue};
use dash_pkc::bls::{
  BlsPublicKey, BlsScChia, BlsScIetf, BlsSchemeKind, BlsSecretKey, BlsShareId, BlsSigShare, BlsSignature,
};
use dash_types::Numeric;
use hex_conservative::DisplayHex;
use serde::Deserialize;

fn corpus() -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_dashbls")
}

// test.cpp:319-332, "Pyecc vector".

#[derive(Deserialize)]
struct PyeccRow {
  sk: String,
  msg: String,
  sig: String,
}

/// `BasicSchemeMPL().Sign(sk, msg)` is the vector's signature, and it verifies.
#[test]
fn pyecc_basic_sign() {
  let rows = corpus().vectors::<PyeccRow>("pyecc");
  assert_eq!(rows.len(), 1);
  for row in rows {
    let sk = BlsSecretKey::<BlsScIetf>::from_bytes(&arr_from_hex(&row.sk)).unwrap();
    let msg = vec_from_hex(&row.msg);
    let sig = sk.sign(&msg);
    assert_eq!(sig.to_bytes().to_lower_hex_string(), row.sig);
    assert_eq!(
      BlsSignature::<BlsScIetf>::from_bytes(&arr_from_hex(&row.sig)).unwrap(),
      sig
    );
    sk.public_key().verify(&msg, &sig).unwrap();
  }
}

// test.cpp:335-402, "Chia test vectors 1 (Basic)".

#[derive(Deserialize)]
struct ChiaRow {
  seed1: String,
  seed2: String,
  msg1: String,
  msg2: String,
  msg3: String,
  msg4: String,
  msg5: String,
  pk1_fp: String,
  pk2_fp: String,
  sig1: String,
  sk1: String,
  pk1: String,
  sig2: String,
  agg_sig1_sig2: String,
  agg_sig3_sig4_sig5: String,
}

/// `G1Element::GetFingerprint`: the first four bytes of the sha256 of the key's
/// serialization (`fLegacy` false), read big-endian.
fn fingerprint(pk: &BlsPublicKey<BlsScIetf>) -> String {
  Sha256::hash(&pk.to_bytes()).to_byte_array()[..4].to_lower_hex_string()
}

#[test]
fn chia_v1_basic() {
  type Sk = BlsSecretKey<BlsScIetf>;
  type Pk = BlsPublicKey<BlsScIetf>;
  type Sig = BlsSignature<BlsScIetf>;

  let rows = corpus().vectors::<ChiaRow>("chia_v1");
  assert_eq!(rows.len(), 1);
  for r in rows {
    let (m1, m2, m3, m4, m5) = (
      vec_from_hex(&r.msg1),
      vec_from_hex(&r.msg2),
      vec_from_hex(&r.msg3),
      vec_from_hex(&r.msg4),
      vec_from_hex(&r.msg5),
    );

    // KeyGen(seed) is the draft-03 derivation.
    let sk1 = Sk::from_ikm(&vec_from_hex(&r.seed1)).unwrap();
    let sk2 = Sk::from_ikm(&vec_from_hex(&r.seed2)).unwrap();
    assert_eq!(sk1.to_bytes().to_lower_hex_string(), r.sk1);
    let (pk1, pk2) = (sk1.public_key(), sk2.public_key());
    assert_eq!(pk1.to_bytes().to_lower_hex_string(), r.pk1);
    assert_eq!(fingerprint(&pk1), r.pk1_fp);
    assert_eq!(fingerprint(&pk2), r.pk2_fp);

    let sig1 = sk1.sign(&m1);
    let sig2 = sk2.sign(&m2);
    assert_eq!(sig1.to_bytes().to_lower_hex_string(), r.sig1);
    assert_eq!(sig2.to_bytes().to_lower_hex_string(), r.sig2);
    // The vector's signatures also decode to what was signed.
    assert_eq!(Sig::from_bytes(&arr_from_hex(&r.sig1)).unwrap(), sig1);
    assert_eq!(Sig::from_bytes(&arr_from_hex(&r.sig2)).unwrap(), sig2);
    assert_eq!(Pk::from_bytes(&arr_from_hex(&r.pk1)).unwrap(), pk1);

    let agg1 = Sig::aggregate(&[&sig1, &sig2]).unwrap();
    assert_eq!(agg1.to_bytes().to_lower_hex_string(), r.agg_sig1_sig2);
    let value = |hex: &str| BlsSigValue::from_canonical(&arr_from_hex(hex), BlsSchemeKind::Basic).unwrap();
    let core = aggregate_signatures_insecure(&[&value(&r.sig1), &value(&r.sig2)]);
    assert_eq!(
      core.to_bytes(BlsSchemeKind::Basic).to_lower_hex_string(),
      r.agg_sig1_sig2
    );
    agg1.verify_aggregates(&[&m1, &m2], &[&pk1, &pk2]).unwrap();
    assert!(sig1.verify_aggregates(&[&m1, &m2], &[&pk1, &pk2]).is_err());
    assert!(pk1.verify(&m1, &sig2).is_err());
    assert!(pk1.verify(&m2, &sig1).is_err());

    let sig3 = sk1.sign(&m3);
    let sig4 = sk1.sign(&m4);
    let sig5 = sk2.sign(&m5);
    let agg2 = Sig::aggregate(&[&sig3, &sig4, &sig5]).unwrap();
    assert_eq!(agg2.to_bytes().to_lower_hex_string(), r.agg_sig3_sig4_sig5);
    agg2.verify_aggregates(&[&m3, &m4, &m5], &[&pk1, &pk1, &pk2]).unwrap();
  }
}

// test.cpp:1253-1322, "Legacy scheme".

#[derive(Deserialize)]
struct ThresholdRow {
  sign_hash_display: String,
  sign_hash_bytes: String,
  threshold_pk: String,
  threshold_sig: String,
}

#[derive(Deserialize)]
struct ShareRow {
  sk: String,
  sig: String,
  id_display: String,
  id_bytes: String,
}

fn legacy_shares(rows: &[ShareRow], id_of: impl Fn(&ShareRow) -> &str) -> Vec<BlsSigShare<BlsScChia>> {
  rows
    .iter()
    .map(|r| {
      let sig = BlsSignature::<BlsScChia>::from_bytes(&arr_from_hex(&r.sig)).unwrap();
      BlsSigShare::new(BlsShareId::from_lendian(arr_from_hex(id_of(r))), sig)
    })
    .collect()
}

/// Core signs the reversed hash and passes the reversed ids; both are the
/// bytes in `*_bytes`, the display form being the source's hex.
#[test]
fn legacy_threshold_gist() {
  let c = corpus();
  let rows = c.vectors::<ShareRow>("legacy_threshold_shares");
  assert_eq!(rows.len(), 10);
  let meta = c.vectors::<ThresholdRow>("legacy_threshold");
  assert_eq!(meta.len(), 1);
  let m = &meta[0];

  let hash: [u8; 32] = arr_from_hex(&m.sign_hash_bytes);
  let mut reversed = arr_from_hex::<32>(&m.sign_hash_display);
  reversed.reverse();
  assert_eq!(hash, reversed, "sign_hash_bytes is the display hex reversed");
  for r in &rows {
    let mut id = arr_from_hex::<32>(&r.id_display);
    id.reverse();
    assert_eq!(
      id,
      arr_from_hex::<32>(&r.id_bytes),
      "id_bytes is the display hex reversed"
    );
  }

  // Every share signs the hash to the listed signature.
  for (i, r) in rows.iter().enumerate() {
    let sk = BlsSecretKey::<BlsScChia>::from_bytes(&arr_from_hex(&r.sk)).unwrap();
    assert_eq!(sk.sign(&hash).to_bytes().to_lower_hex_string(), r.sig, "share {i}");
  }

  // The shares recover the threshold signature, which verifies under the
  // threshold key.
  let shares = legacy_shares(&rows, |r| &r.id_bytes);
  let recovered = BlsSignature::recover_shares(&shares.iter().collect::<Vec<_>>()).unwrap();
  assert_eq!(recovered.to_bytes().to_lower_hex_string(), m.threshold_sig);
  // So does the wrapper's `Recover`, given the same id bytes.
  let sigs: Vec<BlsSigValue> = rows
    .iter()
    .map(|r| BlsSigValue::from_canonical(&arr_from_hex(&r.sig), BlsSchemeKind::Legacy).unwrap())
    .collect();
  let ids: Vec<[u8; 32]> = rows.iter().map(|r| arr_from_hex(&r.id_bytes)).collect();
  let mut core = BlsSigValue::invalid();
  assert!(recover_signature(&mut core, &sigs.iter().collect::<Vec<_>>(), &ids));
  assert_eq!(
    core.to_bytes(BlsSchemeKind::Legacy).to_lower_hex_string(),
    m.threshold_sig
  );
  let pk = BlsPublicKey::<BlsScChia>::from_bytes(&arr_from_hex(&m.threshold_pk)).unwrap();
  pk.verify(&hash, &recovered).unwrap();

  // The display order is not what Core passes: those ids recover another point.
  let wrong = legacy_shares(&rows, |r| &r.id_display);
  let other = BlsSignature::recover_shares(&wrong.iter().collect::<Vec<_>>()).unwrap();
  assert_ne!(other.to_bytes().to_lower_hex_string(), m.threshold_sig);
}

// test.cpp:1519-1621, "CheckValid" and "CheckValid for Legacy".

#[derive(Deserialize)]
struct PointRow {
  point: String,
  valid: bool,
}

/// `G1Element::FromBytes` throws on the non-legacy bad point; the typed decoder
/// and the canonical decode both refuse it.
#[test]
fn check_valid_basic_g1() {
  let rows = corpus().vectors::<PointRow>("check_valid_basic_g1");
  assert_eq!(rows.len(), 1);
  for r in rows {
    assert!(!r.valid);
    let bytes = arr_from_hex(&r.point);
    assert!(BlsPublicKey::<BlsScIetf>::from_bytes(&bytes).is_err());
    assert!(BlsPkValue::from_canonical(&bytes, BlsSchemeKind::Basic).is_none());
  }
}

/// Legacy `FromBytes` and `FromBytesUnchecked` never throw, so both points
/// decode; `IsValid()` (on the curve and in the prime-order subgroup) is the
/// vector's verdict. The typed decoder runs no subgroup test on the legacy
/// path, so the verdict is the point's `usable` test.
#[test]
fn check_valid_legacy_g1() {
  let rows = corpus().vectors::<PointRow>("check_valid_legacy_g1");
  assert_eq!(rows.len(), 2);
  assert_eq!(rows.iter().filter(|r| r.valid).count(), 1);
  for r in rows {
    let bytes = arr_from_hex(&r.point);
    assert!(BlsPublicKey::<BlsScChia>::from_bytes(&bytes).is_ok(), "{}", r.point);
    let value = BlsPkValue::from_canonical(&bytes, BlsSchemeKind::Legacy).unwrap();
    assert_eq!(value.point().unwrap().usable().is_some(), r.valid, "{}", r.point);
  }
}

#[test]
fn check_valid_legacy_g2() {
  let rows = corpus().vectors::<PointRow>("check_valid_legacy_g2");
  assert_eq!(rows.len(), 2);
  assert_eq!(rows.iter().filter(|r| r.valid).count(), 1);
  for r in rows {
    let bytes = arr_from_hex(&r.point);
    assert!(BlsSignature::<BlsScChia>::from_bytes(&bytes).is_ok(), "{}", r.point);
    let value = BlsSigValue::from_canonical(&bytes, BlsSchemeKind::Legacy).unwrap();
    assert_eq!(value.point().unwrap().usable().is_some(), r.valid, "{}", r.point);
  }
}

/// The BLS files directly under `corpus/` with a `PROVENANCE.md` section:
/// every one but `bls_wrapper.json5`, whose header records its origin.
const PROVENANCE_FILES: [&str; 12] = [
  "bls_aggregate",
  "bls_dashbls",
  "bls_dh",
  "bls_hash",
  "bls_ies",
  "bls_keygen",
  "bls_llmq_100",
  "bls_pairing",
  "bls_secure_aggregate",
  "bls_serialize",
  "bls_sign",
  "bls_threshold",
];

/// `corpus/PROVENANCE.md` has a section for every BLS file directly under
/// `corpus/` but `bls_wrapper.json5`, and the sha256 it records is the
/// file's, so a changed or new file fails until its section follows.
#[test]
fn corpus_has_provenance() {
  let dir = format!("{}/corpus", env!("CARGO_MANIFEST_DIR"));
  let provenance = std::fs::read_to_string(format!("{dir}/PROVENANCE.md")).unwrap();
  let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
    .unwrap()
    .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
    .filter_map(|name| name.strip_suffix(".json5").map(str::to_owned))
    .filter(|name| name.starts_with("bls_") && name != "bls_wrapper")
    .collect();
  on_disk.sort();
  let mut listed = PROVENANCE_FILES.map(str::to_owned).to_vec();
  listed.sort();
  assert_eq!(on_disk, listed, "corpus files vs the test's list");
  for file in PROVENANCE_FILES {
    let bytes = std::fs::read(format!("{dir}/{file}.json5")).unwrap();
    let digest = Sha256::hash(&bytes).to_byte_array().to_lower_hex_string();
    let entry = format!("`{file}.json5` sha256 `{digest}`");
    assert!(provenance.contains(&entry), "PROVENANCE.md lacks: {entry}");
  }
}
