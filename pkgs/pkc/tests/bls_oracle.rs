//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's BLS operations, recorded through the consensus oracle, run
//! against this crate. Every file under `corpus/bls_oracle` is checked, and
//! its hash against `PROVENANCE.md`.
//!
//! Each verification row is run two ways and both must give Core's verdict:
//! `bls::core` (serial, Core's rules) always, and the pooled typed verify
//! wherever both decode the operands. Where the crate does not yet compute
//! what Core computes, the row is named in a known-gap list with the slice
//! that closes it, and the test fails once the gap closes.

#![cfg(feature = "bls")]
#![expect(clippy::panic, reason = "test code")]

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
use dash_pkc::bls::core::{
  aggregate_public_keys_insecure, aggregate_public_keys_insecure_pair, aggregate_secret_keys_insecure,
  aggregate_signatures_insecure, aggregate_signatures_insecure_pair, aggregate_signatures_secure, dh_key_exchange,
  ies_key, public_key, public_key_share, recover_signature, secret_key_share, serialize_hash_vector,
  sub_signatures_insecure, verify_insecure, verify_insecure_aggregated, verify_secure_aggregated, BlsIesBlobValue,
  BlsIesMultiBlobs, BlsPkElem, BlsPkValue, BlsSigElem, BlsSigValue, BlsSkValue, BlsVerdict,
};
use dash_pkc::bls::{
  BlsEager, BlsIesBlob, BlsIesBlobBytes, BlsIesMulti, BlsIesMultiBytes, BlsLazy, BlsPublicKey, BlsScChia, BlsScIetf,
  BlsScheme, BlsSchemeKind, BlsSchemeSource, BlsSecretKey, BlsShareId, BlsSigShare, BlsSignature, BlsWire,
  BlsWirePoint, Fr, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN, G1, G2,
};
use dash_types::codec::BaseCodec;
use dash_types::Numeric;
use hex_conservative::DisplayHex;
use rstest::rstest;
use serde::Deserialize;

use std::collections::BTreeMap;

const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;
const DIR: &str = "bls_oracle";

fn corpus(file: &str) -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), &format!("{DIR}/{file}"))
}

fn scheme_name(kind: BlsSchemeKind) -> &'static str {
  match kind {
    LEGACY => "legacy",
    BASIC => "basic",
  }
}

/// An object as Core's eager wrapper reads it under `kind`, `None` where
/// Core's read throws.
fn eager<K: BlsWire<N>, const N: usize>(hex: &str, kind: BlsSchemeKind) -> Option<dash_pkc::bls::BlsValue<K, N>> {
  BlsEager::<K, N>::decode(&arr_from_hex(hex), BlsSchemeSource::Version(kind))
    .ok()
    .map(BlsEager::into_value)
}

fn pk_value(hex: &str, kind: BlsSchemeKind) -> BlsPkValue {
  eager(hex, kind).unwrap_or_else(|| panic!("Core reads pk {hex}"))
}

fn sig_value(hex: &str, kind: BlsSchemeKind) -> BlsSigValue {
  eager(hex, kind).unwrap_or_else(|| panic!("Core reads sig {hex}"))
}

fn sk_value(hex: &str, kind: BlsSchemeKind) -> BlsSkValue {
  eager(hex, kind).unwrap_or_else(|| panic!("Core reads sk {hex}"))
}

/// Each object as Core's eager wrapper reads it under `kind`.
fn read_all<T>(hexes: &[String], kind: BlsSchemeKind, read: fn(&str, BlsSchemeKind) -> T) -> Vec<T> {
  hexes.iter().map(|h| read(h, kind)).collect()
}

/// A valid object's serialization under `kind`, `None` for an invalid one.
fn valid_hex<K: BlsWire<N>, const N: usize>(
  value: &dash_pkc::bls::BlsValue<K, N>,
  kind: BlsSchemeKind,
) -> Option<String> {
  value.is_valid().then(|| value.to_bytes(kind).to_lower_hex_string())
}

fn hash(hex: &str) -> [u8; 32] {
  arr_from_hex(hex)
}

/// A participant id from its stored uint256 bytes.
fn share_id(hex: &str) -> BlsShareId {
  BlsShareId::from_lendian(arr_from_hex(hex))
}

/// The typed key or signature, `None` where the typed decoder refuses it.
fn typed_pk<S: BlsScheme>(hex: &str) -> Option<BlsPublicKey<S>> {
  BlsPublicKey::from_bytes(&arr_from_hex(hex)).ok()
}

fn typed_sig<S: BlsScheme>(hex: &str) -> Option<BlsSignature<S>> {
  BlsSignature::from_bytes(&arr_from_hex(hex)).ok()
}

fn typed_sk<S: BlsScheme>(hex: &str) -> BlsSecretKey<S> {
  BlsSecretKey::from_bytes(&arr_from_hex(hex)).unwrap_or_else(|e| panic!("sk {hex}: {e:?}"))
}

fn msg<S: BlsScheme>(h: &[u8; 32]) -> &S::Msg {
  S::msg_ref(h)
}

/// Asserts `core`'s verdict and, where the operands decode, the pooled one.
fn assert_verdict(label: &str, core: BlsVerdict, pooled: Option<bool>, ok: bool) {
  assert_eq!(core, BlsVerdict::from(ok), "{label}: bls::core");
  if let Some(pooled) = pooled {
    assert_eq!(pooled, ok, "{label}: pooled verify");
  }
}

// hash_to_g2.json5

#[derive(Deserialize)]
struct HashRow {
  msg: String,
  point: String,
}

/// Core's hash to G2 is the signature of the secret key 1.
fn assert_hash_to_g2<S: BlsScheme>(kind: BlsSchemeKind) {
  let mut one = [0u8; 32];
  one[31] = 1;
  let sk = BlsSecretKey::<S>::from_bytes(&one).unwrap_or_else(|e| panic!("sk 1: {e:?}"));
  for row in corpus("hash_to_g2").vectors::<HashRow>(scheme_name(kind)) {
    let sig = sk.sign(msg::<S>(&hash(&row.msg)));
    assert_eq!(sig.to_bytes().to_lower_hex_string(), row.point, "hash of {}", row.msg);
  }
}

// sign.json5

#[derive(Deserialize)]
struct KeyRow {
  sk: String,
  pk: String,
}

#[derive(Deserialize)]
struct SignRow {
  key: usize,
  msg: String,
  sig: String,
}

#[derive(Deserialize)]
struct VerifyRow {
  pk: String,
  sig: String,
  msg: String,
  ok: bool,
  note: String,
}

fn assert_sign<S: BlsScheme>(kind: BlsSchemeKind) {
  let c = corpus("sign").scope(scheme_name(kind));
  let keys = c.vectors::<KeyRow>("keys");
  for key in &keys {
    assert_eq!(
      typed_sk::<S>(&key.sk).public_key().to_bytes().to_lower_hex_string(),
      key.pk
    );
  }
  for row in c.vectors::<SignRow>("sign") {
    let sig = typed_sk::<S>(&keys[row.key].sk).sign(msg::<S>(&hash(&row.msg)));
    assert_eq!(
      sig.to_bytes().to_lower_hex_string(),
      row.sig,
      "key {} msg {}",
      row.key,
      row.msg
    );
  }
  for row in c.vectors::<VerifyRow>("verify") {
    let h = hash(&row.msg);
    let core = verify_insecure(&sig_value(&row.sig, kind), &pk_value(&row.pk, kind), &h, kind);
    let pooled = typed_pk::<S>(&row.pk)
      .zip(typed_sig::<S>(&row.sig))
      .map(|(pk, sig)| pk.verify(msg::<S>(&h), &sig).is_ok());
    assert_verdict(&row.note, core, pooled, row.ok);
  }
}

// aggregate.json5

#[derive(Deserialize)]
struct AggSkRow {
  sks: Vec<String>,
  agg: Option<String>,
}

#[derive(Deserialize)]
struct AggPkRow {
  pks: Vec<String>,
  agg: Option<String>,
}

#[derive(Deserialize)]
struct AggSigRow {
  sigs: Vec<String>,
  agg: String,
}

#[derive(Deserialize)]
struct SubRow {
  sig: String,
  other: String,
  out: Option<String>,
}

#[derive(Deserialize)]
struct SameMsgRow {
  pks: Vec<String>,
  sig: String,
  msg: String,
  ok: bool,
  note: String,
}

#[derive(Deserialize)]
struct DistinctRow {
  pks: Vec<String>,
  msgs: Vec<String>,
  sig: String,
  ok: bool,
  note: String,
}

fn typed_pks<S: BlsScheme>(hexes: &[String]) -> Vec<BlsPublicKey<S>> {
  hexes
    .iter()
    .map(|h| typed_pk(h).unwrap_or_else(|| panic!("pk {h}")))
    .collect()
}

fn typed_sigs<S: BlsScheme>(hexes: &[String]) -> Vec<BlsSignature<S>> {
  hexes
    .iter()
    .map(|h| typed_sig(h).unwrap_or_else(|| panic!("sig {h}")))
    .collect()
}

fn assert_aggregate<S: BlsScheme>(kind: BlsSchemeKind) {
  let c = corpus("aggregate").scope(scheme_name(kind));
  for row in c.vectors::<AggSkRow>("sk") {
    let sks: Vec<BlsSecretKey<S>> = row.sks.iter().map(|h| typed_sk(h)).collect();
    let agg = BlsSecretKey::aggregate(&sks.iter().collect::<Vec<_>>()).ok();
    let got = agg.map(|sk| sk.to_bytes().to_lower_hex_string());
    assert_eq!(got, row.agg, "aggregate of {} secret keys", row.sks.len());
    let values = read_all(&row.sks, kind, sk_value);
    let core = aggregate_secret_keys_insecure(&values.iter().collect::<Vec<_>>());
    assert_eq!(
      valid_hex(&core, kind),
      row.agg,
      "bls::core: {} secret keys",
      row.sks.len()
    );
  }
  for row in c.vectors::<AggPkRow>("pk") {
    let pks = typed_pks::<S>(&row.pks);
    let agg = BlsPublicKey::aggregate(&pks.iter().collect::<Vec<_>>()).ok();
    let got = agg.map(|pk| pk.to_bytes().to_lower_hex_string());
    assert_eq!(got, row.agg, "aggregate of {} public keys", row.pks.len());
    let values = read_all(&row.pks, kind, pk_value);
    let core = aggregate_public_keys_insecure(&values.iter().collect::<Vec<_>>());
    assert_eq!(
      valid_hex(&core, kind),
      row.agg,
      "bls::core: {} public keys",
      row.pks.len()
    );
  }
  for row in c.vectors::<AggSigRow>("sig") {
    let sigs = typed_sigs::<S>(&row.sigs);
    let agg = BlsSignature::aggregate(&sigs.iter().collect::<Vec<_>>()).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(agg.to_bytes().to_lower_hex_string(), row.agg);
    let values = read_all(&row.sigs, kind, sig_value);
    let core = aggregate_signatures_insecure(&values.iter().collect::<Vec<_>>());
    assert_eq!(
      valid_hex(&core, kind).as_ref(),
      Some(&row.agg),
      "bls::core: {} signatures",
      row.sigs.len()
    );
  }
  for row in c.vectors::<SubRow>("sub") {
    let (sig, other) = (
      typed_sigs::<S>(core::slice::from_ref(&row.sig)),
      typed_sigs::<S>(core::slice::from_ref(&row.other)),
    );
    let got = sig[0]
      .sub_insecure(&other[0])
      .ok()
      .map(|s| s.to_bytes().to_lower_hex_string());
    assert_eq!(got, row.out, "SubInsecure");
    let core = sub_signatures_insecure(&sig_value(&row.sig, kind), &sig_value(&row.other, kind));
    assert_eq!(valid_hex(&core, kind), row.out, "bls::core SubInsecure");
  }
  for row in c.vectors::<SameMsgRow>("same_msg") {
    // Core's same-message check: VerifyInsecure against the summed key.
    let h = hash(&row.msg);
    let pks = typed_pks::<S>(&row.pks);
    let refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let agg = BlsPublicKey::aggregate(&refs).unwrap_or_else(|e| panic!("{e:?}"));
    let agg = pk_value(&agg.to_bytes().to_lower_hex_string(), kind);
    let core = verify_insecure(&sig_value(&row.sig, kind), &agg, &h, kind);
    let pooled = typed_sig::<S>(&row.sig).map(|sig| sig.fast_verify_aggregates(msg::<S>(&h), &refs).is_ok());
    assert_verdict(&format!("{} keys, {}", row.pks.len(), row.note), core, pooled, row.ok);
  }
  for row in c.vectors::<DistinctRow>("distinct") {
    let label = format!("{} keys, {}", row.pks.len(), row.note);
    let hs: Vec<[u8; 32]> = row.msgs.iter().map(|m| hash(m)).collect();
    let values: Vec<BlsPkValue> = row.pks.iter().map(|p| pk_value(p, kind)).collect();
    let core = verify_insecure_aggregated(
      &sig_value(&row.sig, kind),
      &values.iter().collect::<Vec<_>>(),
      &hs,
      kind,
    );
    let pks = typed_pks::<S>(&row.pks);
    let msgs: Vec<&S::Msg> = hs.iter().map(msg::<S>).collect();
    let pooled =
      typed_sig::<S>(&row.sig).map(|sig| sig.verify_aggregates(&msgs, &pks.iter().collect::<Vec<_>>()).is_ok());
    // The typed legacy verify accepts a repeated message, which Core's legacy
    // scheme does too; the typed basic verify refuses it, as Core does.
    assert_verdict(&label, core, pooled, row.ok);
  }
}

// secure.json5

#[derive(Deserialize)]
struct SecureAggRow {
  sigs: Vec<String>,
  pks: Vec<String>,
  agg: Option<String>,
  note: String,
}

#[derive(Deserialize)]
struct SecureVerifyRow {
  sig: String,
  pks: Vec<String>,
  msg: String,
  ok: bool,
  note: String,
}

fn assert_secure<S: BlsScheme>(kind: BlsSchemeKind) {
  let c = corpus("secure").scope(scheme_name(kind));
  for row in c.vectors::<SecureAggRow>("aggregate") {
    let sigs = typed_sigs::<S>(&row.sigs);
    let pks = typed_pks::<S>(&row.pks);
    let agg = BlsSignature::secure_aggregate(&sigs.iter().collect::<Vec<_>>(), &pks.iter().collect::<Vec<_>>()).ok();
    let got = agg.map(|s| s.to_bytes().to_lower_hex_string());
    assert_eq!(got, row.agg, "{}", row.note);
    let (sigs, pks) = (read_all(&row.sigs, kind, sig_value), read_all(&row.pks, kind, pk_value));
    let core = aggregate_signatures_secure(&sigs.iter().collect::<Vec<_>>(), &pks.iter().collect::<Vec<_>>(), kind);
    assert_eq!(valid_hex(&core, kind), row.agg, "bls::core: {}", row.note);
  }
  for row in c.vectors::<SecureVerifyRow>("verify") {
    let h = hash(&row.msg);
    let values: Vec<BlsPkValue> = row.pks.iter().map(|p| pk_value(p, kind)).collect();
    let core = verify_secure_aggregated(&sig_value(&row.sig, kind), &values.iter().collect::<Vec<_>>(), &h, kind);
    let pks = typed_pks::<S>(&row.pks);
    let pooled = typed_sig::<S>(&row.sig).map(|sig| {
      sig
        .secure_verify_aggregates(msg::<S>(&h), &pks.iter().collect::<Vec<_>>())
        .is_ok()
    });
    assert_verdict(&row.note, core, pooled, row.ok);
  }
}

// threshold.json5

#[derive(Deserialize)]
struct ThresholdCase {
  t: usize,
  msk: Vec<String>,
  mpk: Vec<String>,
  ids: Vec<String>,
  sk_shares: Vec<Option<String>>,
  pk_shares: Vec<Option<String>>,
  msg: String,
  master_sig: String,
  sig_shares: Vec<Option<String>>,
  recover: Vec<RecoverRow>,
}

#[derive(Deserialize)]
struct RecoverRow {
  subset: Vec<usize>,
  sig: Option<String>,
  is_master: bool,
}

fn assert_threshold<S: BlsScheme>(kind: BlsSchemeKind) {
  for case in corpus("threshold").vectors::<ThresholdCase>(scheme_name(kind)) {
    let label = format!("t = {}", case.t);
    let msk: Vec<BlsSecretKey<S>> = case.msk.iter().map(|h| typed_sk(h)).collect();
    let mpk = typed_pks::<S>(&case.mpk);
    for (pk, sk) in mpk.iter().zip(&msk) {
      assert_eq!(&sk.public_key(), pk, "{label}: master public key");
    }
    let h = hash(&case.msg);
    assert_eq!(
      msk[0].sign(msg::<S>(&h)).to_bytes().to_lower_hex_string(),
      case.master_sig
    );
    let msk_refs: Vec<&BlsSecretKey<S>> = msk.iter().collect();
    let mpk_refs: Vec<&BlsPublicKey<S>> = mpk.iter().collect();
    let (msk_values, mpk_values) = (read_all(&case.msk, kind, sk_value), read_all(&case.mpk, kind, pk_value));
    let ids: Vec<[u8; 32]> = case.ids.iter().map(|id| arr_from_hex(id)).collect();
    for (i, id) in ids.iter().enumerate() {
      // Core keeps a failed receiver's element; a fresh one holds the default.
      let mut sk = BlsSkValue::invalid();
      let ok = secret_key_share(&mut sk, &msk_values.iter().collect::<Vec<_>>(), id);
      assert_eq!(ok, sk.is_valid(), "{label}: bls::core secret key share {i}");
      assert_eq!(
        valid_hex(&sk, kind),
        case.sk_shares[i],
        "{label}: bls::core secret key share {i}"
      );
      let mut pk = BlsPkValue::invalid();
      let ok = public_key_share(&mut pk, &mpk_values.iter().collect::<Vec<_>>(), id);
      assert_eq!(ok, pk.is_valid(), "{label}: bls::core public key share {i}");
      assert_eq!(
        valid_hex(&pk, kind),
        case.pk_shares[i],
        "{label}: bls::core public key share {i}"
      );
    }
    for (i, id) in case.ids.iter().enumerate() {
      let id = share_id(id);
      let sk = BlsSecretKey::derive_share(&msk_refs, &id)
        .ok()
        .map(|s| s.to_bytes().to_lower_hex_string());
      let pk = BlsPublicKey::derive_share(&mpk_refs, &id)
        .ok()
        .map(|p| p.to_bytes().to_lower_hex_string());
      assert_eq!(sk, case.sk_shares[i], "{label}: secret key share {i}");
      assert_eq!(pk, case.pk_shares[i], "{label}: public key share {i}");
      if let Some(share) = &sk {
        let sig = typed_sk::<S>(share).sign(msg::<S>(&h)).to_bytes().to_lower_hex_string();
        assert_eq!(Some(sig), case.sig_shares[i], "{label}: signature share {i}");
      }
    }
    for row in &case.recover {
      let shares: Vec<BlsSigShare<S>> = row
        .subset
        .iter()
        .map(|&i| {
          let sig = case.sig_shares[i]
            .as_deref()
            .unwrap_or_else(|| panic!("{label}: share {i}"));
          BlsSigShare::new(share_id(&case.ids[i]), typed_sigs::<S>(&[sig.to_owned()]).remove(0))
        })
        .collect();
      let got = BlsSignature::recover_shares(&shares.iter().collect::<Vec<_>>()).ok();
      let got = got.map(|s| s.to_bytes().to_lower_hex_string());
      assert_eq!(got, row.sig, "{label}: recovery from {:?}", row.subset);
      let sigs: Vec<BlsSigValue> = row
        .subset
        .iter()
        .map(|&i| sig_value(need(case.sig_shares[i].as_deref(), &label, "share"), kind))
        .collect();
      let subset_ids: Vec<[u8; 32]> = row.subset.iter().map(|&i| ids[i]).collect();
      let mut recovered = BlsSigValue::invalid();
      let ok = recover_signature(&mut recovered, &sigs.iter().collect::<Vec<_>>(), &subset_ids);
      assert_eq!(
        ok,
        recovered.is_valid(),
        "{label}: bls::core recovery from {:?}",
        row.subset
      );
      assert_eq!(
        valid_hex(&recovered, kind),
        row.sig,
        "{label}: bls::core recovery from {:?}",
        row.subset
      );
      assert_eq!(row.sig.as_deref() == Some(&case.master_sig[..]), row.is_master);
    }
  }
}

// ies.json5

#[derive(Deserialize)]
struct IesRow {
  eph_sk: String,
  iv_seed: String,
  recipients: Vec<String>,
  plaintexts: Vec<String>,
  out: Option<String>,
  note: String,
  decrypt: Vec<DecryptRow>,
}

#[derive(Deserialize)]
struct DecryptRow {
  idx: usize,
  sk: String,
  plain: Option<String>,
}

#[derive(Deserialize)]
struct BlobRow {
  idx: usize,
  sk: String,
  blob: String,
  plain: Option<String>,
}

fn decode_bytes<T: BaseCodec>(hex: &str) -> T {
  let bytes = vec_from_hex(hex);
  let mut data = &bytes[..];
  let out = T::decode(&mut data).unwrap_or_else(|e| panic!("decode {hex}: {e:?}"));
  assert!(data.is_empty(), "trailing bytes in {hex}");
  out
}

/// Compares a decryption with Core's, through the known gap of the empty
/// plaintext, which Core opens to nothing and the crate refuses (BS11b).
fn assert_opened(label: &str, got: Option<String>, core: Option<&String>) {
  match core {
    Some(plain) if plain.is_empty() => assert!(got.is_none(), "{label}: empty plaintext gap closed"),
    _ => assert_eq!(got.as_ref(), core, "{label}"),
  }
}

fn assert_ies<S: BlsScheme>(kind: BlsSchemeKind) {
  let c = corpus("ies").scope(scheme_name(kind));
  for row in c.vectors::<IesRow>("multi") {
    // Core encrypts no misaligned plaintext (the crate's encryption is
    // internal, so only Core's output is checked here).
    let Some(out) = &row.out else {
      assert_eq!(row.note, "misaligned", "Core refused to encrypt");
      continue;
    };
    assert_eq!(row.decrypt.len(), row.plaintexts.len() + 2, "{}", row.note);
    let multi: BlsIesMulti<S> = decode_bytes::<BlsIesMultiBytes<S>>(out)
      .try_into()
      .unwrap_or_else(|e| panic!("{}: {e:?}", row.note));
    assert_eq!(
      multi.ephemeral_pk(),
      &typed_sk::<S>(&row.eph_sk).public_key(),
      "{}",
      row.note
    );
    assert_eq!(multi.iv_seed().to_lower_hex_string(), row.iv_seed);
    assert_eq!(multi.blobs().len(), row.recipients.len());
    for (i, (plain, d)) in row.plaintexts.iter().zip(&row.decrypt).enumerate() {
      assert_eq!(d.idx, i, "{}", row.note);
      assert_eq!(
        d.plain.as_ref(),
        Some(plain),
        "{}: Core opens recipient {}",
        row.note,
        d.idx
      );
    }
    for d in &row.decrypt {
      let got = typed_sk::<S>(&d.sk)
        .ies_decrypt_multi(&multi, d.idx)
        .ok()
        .map(|p| p.to_lower_hex_string());
      let label = format!("{}: decrypt {} with {}", row.note, d.idx, d.sk);
      assert_opened(&label, got, d.plain.as_ref());
    }
  }
  for row in c.vectors::<BlobRow>("blob") {
    let blob: BlsIesBlob<S> = decode_bytes::<BlsIesBlobBytes<S>>(&row.blob)
      .try_into()
      .unwrap_or_else(|e| panic!("blob: {e:?}"));
    let got = typed_sk::<S>(&row.sk)
      .ies_decrypt(&blob, row.idx)
      .ok()
      .map(|p| p.to_lower_hex_string());
    assert_opened(&format!("blob {}", row.idx), got, row.plain.as_ref());
  }
}

// decode.json5

#[derive(Deserialize)]
struct DecodeRow {
  kind: String,
  class: String,
  #[serde(rename = "in")]
  input: String,
  eager_legacy: String,
  eager_basic: String,
  lazy_legacy: Option<String>,
  lazy_basic: Option<String>,
}

/// Core's eager read under `kind` in the corpus notation.
fn eager_outcome<K: BlsWire<N>, const N: usize>(input: &[u8; N], kind: BlsSchemeKind) -> String {
  match BlsEager::<K, N>::decode(input, BlsSchemeSource::Version(kind)) {
    Err(_) => "T".into(),
    Ok(e) if !e.is_valid() => "I".into(),
    Ok(e) => format!("V:{}", e.to_bytes(kind).as_hex()),
  }
}

/// Core's lazy read: the bytes are kept, and validity is `Get`'s.
fn lazy_outcome<K: BlsWirePoint<N>, const N: usize>(input: &[u8; N], kind: BlsSchemeKind) -> String {
  let lazy = BlsLazy::<K, N>::from_bytes(input, BlsSchemeSource::Version(kind));
  if lazy.get().is_valid() {
    format!("V:{}", lazy.to_bytes().as_hex())
  } else {
    "I".into()
  }
}

fn assert_decode_row<K: BlsWire<N>, const N: usize>(row: &DecodeRow) -> [String; 2] {
  let input: [u8; N] = arr_from_hex(&row.input);
  [
    eager_outcome::<K, N>(&input, LEGACY),
    eager_outcome::<K, N>(&input, BASIC),
  ]
}

fn assert_lazy_row<K: BlsWirePoint<N>, const N: usize>(row: &DecodeRow) -> [Option<String>; 2] {
  let input: [u8; N] = arr_from_hex(&row.input);
  [
    Some(lazy_outcome::<K, N>(&input, LEGACY)),
    Some(lazy_outcome::<K, N>(&input, BASIC)),
  ]
}

/// A1 section 1.4.1's outcome table classes, decoded by the oracle eagerly
/// and lazily under both schemes.
fn assert_decode() {
  for row in corpus("decode").vectors::<DecodeRow>("rows") {
    let label = format!("{} {} {}", row.kind, row.class, row.input);
    let (eager, lazy) = match row.kind.as_str() {
      "pk" => (
        assert_decode_row::<G1, BLS_PK_LEN>(&row),
        assert_lazy_row::<G1, BLS_PK_LEN>(&row),
      ),
      "sig" => (
        assert_decode_row::<G2, BLS_SIG_LEN>(&row),
        assert_lazy_row::<G2, BLS_SIG_LEN>(&row),
      ),
      "sk" => (assert_decode_row::<Fr, BLS_SK_LEN>(&row), [None, None]),
      other => panic!("kind {other}"),
    };
    assert_eq!(
      eager,
      [row.eager_legacy.clone(), row.eager_basic.clone()],
      "{label}: eager"
    );
    assert_eq!(lazy, [row.lazy_legacy.clone(), row.lazy_basic.clone()], "{label}: lazy");
  }
}

// edge.json5

#[derive(Deserialize)]
struct EdgeRow {
  op: String,
  decode: String,
  flag: String,
  sig: String,
  pks: Vec<String>,
  msgs: Vec<String>,
  ok: bool,
  note: String,
}

fn scheme_named(name: &str) -> BlsSchemeKind {
  match name {
    "legacy" => LEGACY,
    "basic" => BASIC,
    other => panic!("scheme {other}"),
  }
}

/// Verifications over invalid and exotic operands, decoded under one scheme
/// and verified under either flag. An exotic operand under the legacy flag
/// is a known gap: Core pairs it with relic's arithmetic, which the crate
/// does not reproduce yet (BS11a-4), so `bls::core` must answer
/// `Unsupported` there until that lands.
fn assert_edge() {
  let rows = corpus("edge").vectors::<EdgeRow>("rows");
  let mut gaps = 0;
  for row in &rows {
    let (decode, flag) = (scheme_named(&row.decode), scheme_named(&row.flag));
    let sig = sig_value(&row.sig, decode);
    let pks: Vec<BlsPkValue> = row.pks.iter().map(|p| pk_value(p, decode)).collect();
    let pk_refs: Vec<&BlsPkValue> = pks.iter().collect();
    let hs: Vec<[u8; 32]> = row.msgs.iter().map(|m| hash(m)).collect();
    let core = match row.op.as_str() {
      "insecure" => verify_insecure(&sig, &pks[0], &hs[0], flag),
      "aggregated" => verify_insecure_aggregated(&sig, &pk_refs, &hs, flag),
      "secure" => verify_secure_aggregated(&sig, &pk_refs, &hs[0], flag),
      other => panic!("op {other}"),
    };
    let label = format!("{} {} under {}: {}", row.op, row.decode, row.flag, row.note);
    let exotic = sig.point().is_some_and(|p| p.usable().is_none())
      || pks.iter().any(|pk| pk.point().is_some_and(|p| p.usable().is_none()));
    if flag == LEGACY && exotic {
      gaps += 1;
      assert_eq!(core, BlsVerdict::Unsupported, "{label}: the relic gap closed");
    } else {
      assert_verdict(&label, core, None, row.ok);
    }
  }
  assert!(
    0 < gaps && gaps < rows.len(),
    "{gaps} of {} rows in the relic gap",
    rows.len()
  );
}

// relic.json5 and arith.json5

#[derive(Deserialize)]
struct RelicRow {
  probe: String,
  scheme: String,
  note: String,
  steps: Vec<RelicStep>,
}

#[derive(Deserialize)]
struct RelicStep {
  op: String,
  flag: Option<String>,
  kind: Option<String>,
  input: Option<String>,
  a: Option<usize>,
  b: Option<usize>,
  k: Option<String>,
  sig: Option<usize>,
  pk: Option<usize>,
  sk: Option<usize>,
  recv: Option<usize>,
  items: Option<Vec<usize>>,
  sigs: Option<Vec<usize>>,
  keys: Option<Vec<usize>>,
  id: Option<String>,
  ids: Option<Vec<String>>,
  seed: Option<String>,
  plain: Option<Vec<String>>,
  idx: Option<usize>,
  data: Option<String>,
  #[serde(default)]
  pair: bool,
  msg: Option<String>,
  status: i32,
  code: i32,
  out: String,
  log: Vec<(String, i32)>,
}

fn need<'a, T: ?Sized>(value: Option<&'a T>, label: &str, what: &str) -> &'a T {
  value.unwrap_or_else(|| panic!("{label}: no {what}"))
}

/// A register of a step script: the object a step left, as Core's wrapper
/// holds it, with its `GetHash()` cache. A step that stores nothing leaves
/// an empty register, so registers stay indexed by step.
#[derive(Clone)]
enum Obj {
  Empty,
  Sk(BlsSkValue),
  Pk(BlsPkValue),
  Sig(BlsSigValue),
}

#[derive(Clone)]
struct Reg {
  obj: Obj,
  hash: Option<[u8; 32]>,
}

impl From<Obj> for Reg {
  fn from(obj: Obj) -> Self {
    Self { obj, hash: None }
  }
}

impl Obj {
  fn is_valid(&self) -> bool {
    match self {
      Self::Empty => panic!("an empty register"),
      Self::Sk(v) => v.is_valid(),
      Self::Pk(v) => v.is_valid(),
      Self::Sig(v) => v.is_valid(),
    }
  }

  /// `ToBytes(scheme)`: zeros when invalid.
  fn bytes(&self, kind: BlsSchemeKind) -> Vec<u8> {
    match self {
      Self::Empty => panic!("an empty register"),
      Self::Sk(v) => v.to_bytes(kind).to_vec(),
      Self::Pk(v) => v.to_bytes(kind).to_vec(),
      Self::Sig(v) => v.to_bytes(kind).to_vec(),
    }
  }

  /// `GetHash()` under `kind`, uncached.
  fn serialize_hash(&self, kind: BlsSchemeKind) -> [u8; 32] {
    match self {
      Self::Empty => panic!("an empty register"),
      Self::Sk(v) => v.serialize_hash(kind),
      Self::Pk(v) => v.serialize_hash(kind),
      Self::Sig(v) => v.serialize_hash(kind),
    }
    .to_lendian()
  }

  /// Core's status for a destination op: `ORACLE_OK` when the object is
  /// valid, else `ORACLE_REJECT`.
  fn status(&self) -> i32 {
    i32::from(!self.is_valid())
  }
}

/// `ADD`, `NEG` and `MUL` on registers' elements, whatever their validity.
fn elem_op(label: &str, op: &str, a: &Obj, b: Option<&Obj>, k: Option<&str>) -> Obj {
  let k = || arr_from_hex::<32>(need(k, label, "k"));
  match (a, b) {
    (Obj::Pk(a), b) => {
      let a = BlsPkElem::from_impl(a);
      Obj::Pk(
        match (op, b) {
          ("add", Some(Obj::Pk(b))) => a.add(&BlsPkElem::from_impl(b)),
          ("neg", None) => a.neg(),
          ("mul", None) => a.mul(&k()),
          _ => panic!("{label}: operands"),
        }
        .into(),
      )
    }
    (Obj::Sig(a), b) => {
      let a = BlsSigElem::from_impl(a);
      Obj::Sig(
        match (op, b) {
          ("add", Some(Obj::Sig(b))) => a.add(&BlsSigElem::from_impl(b)),
          ("neg", None) => a.neg(),
          ("mul", None) => a.mul(&k()),
          _ => panic!("{label}: operands"),
        }
        .into(),
      )
    }
    _ => panic!("{label}: operands"),
  }
}

/// `EQ` (the wrapper's `operator==`) and `IMPL_EQ` (the elements').
fn eq_op(label: &str, op: &str, a: &Obj, b: &Obj) -> bool {
  match (op, a, b) {
    ("eq", Obj::Pk(a), Obj::Pk(b)) => a.core_eq(b),
    ("eq", Obj::Sig(a), Obj::Sig(b)) => a.core_eq(b),
    ("impl_eq", Obj::Pk(a), Obj::Pk(b)) => BlsPkElem::from_impl(a).core_eq(&BlsPkElem::from_impl(b)),
    ("impl_eq", Obj::Sig(a), Obj::Sig(b)) => BlsSigElem::from_impl(a).core_eq(&BlsSigElem::from_impl(b)),
    _ => panic!("{label}: operands"),
  }
}

/// `ISVALID`: the wrapper's `IsValid()`, then its element's.
fn is_valid_op(label: &str, a: &Obj) -> [bool; 2] {
  match a {
    Obj::Pk(v) => [v.is_valid(), BlsPkElem::from_impl(v).is_valid()],
    Obj::Sig(v) => [v.is_valid(), BlsSigElem::from_impl(v).is_valid()],
    _ => panic!("{label}: operands"),
  }
}

/// `AGG_PK` and `AGG_SIG`: the span form, invalid when empty, or the pair
/// form, which Core asserts on an invalid side (`ORACLE_E_ARG`, nothing
/// stored).
fn agg_op(label: &str, op: &str, items: &[&Obj], pair: bool) -> Option<Obj> {
  if pair && items.iter().any(|o| !o.is_valid()) {
    return None;
  }
  let pks: Option<Vec<&BlsPkValue>> = items
    .iter()
    .map(|o| if let Obj::Pk(v) = o { Some(v) } else { None })
    .collect();
  let sigs: Option<Vec<&BlsSigValue>> = items
    .iter()
    .map(|o| if let Obj::Sig(v) = o { Some(v) } else { None })
    .collect();
  Some(match (op, pair) {
    ("agg_pk", false) => Obj::Pk(aggregate_public_keys_insecure(need(pks.as_deref(), label, "keys"))),
    ("agg_pk", true) => match need(pks.as_deref(), label, "keys") {
      [a, b] => Obj::Pk(aggregate_public_keys_insecure_pair(a, b)),
      _ => panic!("{label}: a pair"),
    },
    (_, false) => Obj::Sig(aggregate_signatures_insecure(need(
      sigs.as_deref(),
      label,
      "signatures",
    ))),
    (_, true) => match need(sigs.as_deref(), label, "signatures") {
      [a, b] => Obj::Sig(aggregate_signatures_insecure_pair(a, b)),
      _ => panic!("{label}: a pair"),
    },
  })
}

/// `DHKeyExchange` on a fresh wrapper, or on a copy of `recv` (`INPLACE`),
/// which keeps its element when it fails. A valid product's IES key is the
/// first 32 bytes of its basic encoding.
fn dh_op(label: &str, sk: &Obj, pk: &Obj, recv: Option<&Obj>) -> Obj {
  let (Obj::Sk(sk), Obj::Pk(pk)) = (sk, pk) else {
    panic!("{label}: operands");
  };
  let mut out = match recv {
    Some(Obj::Pk(v)) => v.clone(),
    None => BlsPkValue::invalid(),
    _ => panic!("{label}: receiver"),
  };
  let ok = dh_key_exchange(&mut out, sk, pk);
  assert_eq!(ok, out.is_valid(), "{label}: the receiver");
  match ies_key(sk, pk) {
    Some(key) => assert_eq!(key[..], out.to_bytes(BASIC)[..32], "{label}: the IES key"),
    None => assert!(!ok, "{label}: the IES key"),
  }
  Obj::Pk(out)
}

fn sks_at<'a>(regs: &'a [Reg], items: &[usize], label: &str) -> Vec<&'a BlsSkValue> {
  items
    .iter()
    .map(|&i| match &regs[i].obj {
      Obj::Sk(v) => v,
      _ => panic!("{label}: secret key operand {i}"),
    })
    .collect()
}

fn pks_at<'a>(regs: &'a [Reg], items: &[usize], label: &str) -> Vec<&'a BlsPkValue> {
  items
    .iter()
    .map(|&i| match &regs[i].obj {
      Obj::Pk(v) => v,
      _ => panic!("{label}: key operand {i}"),
    })
    .collect()
}

fn sigs_at<'a>(regs: &'a [Reg], items: &[usize], label: &str) -> Vec<&'a BlsSigValue> {
  items
    .iter()
    .map(|&i| match &regs[i].obj {
      Obj::Sig(v) => v,
      _ => panic!("{label}: signature operand {i}"),
    })
    .collect()
}

/// Runs a step script's every step on `BlsValue`/`BlsElem` over registers
/// that hold what the earlier steps left, with relic's code `RLC_OK` after
/// every step and every logged call. `gaps` counts the verifications on an
/// exotic operand under the legacy flag, `Unsupported` until BS11a-4.
fn assert_steps(file: &str) -> usize {
  let rows = corpus(file).vectors::<RelicRow>("rows");
  let mut gaps = 0;
  for row in &rows {
    let scheme = scheme_named(&row.scheme);
    let mut regs: Vec<Reg> = Vec::new();
    for (i, step) in row.steps.iter().enumerate() {
      let label = format!("{file} {} ({}) step {i} {}", row.probe, row.note, step.op);
      assert_eq!(step.code, 0, "{label}: relic's code");
      assert!(step.log.iter().all(|(_, code)| *code == 0), "{label}: {:?}", step.log);
      // Decoding runs outside the log window; an op on an invalid wrapper
      // may make no relic call inside it.
      assert!(step.op != "decode" || step.log.is_empty(), "{label}: the log window");
      let flag = step.flag.as_deref().map_or(scheme, scheme_named);
      let at = |index: Option<usize>| &regs[*need(index.as_ref(), &label, "operand")].obj;
      let (status, out, made) = match step.op.as_str() {
        "decode" => {
          let input = need(step.input.as_deref(), &label, "input");
          let obj = match step.kind.as_deref() {
            Some("pk") => eager(input, flag).map(Obj::Pk),
            Some("sig") => eager(input, flag).map(Obj::Sig),
            Some("sk") => eager(input, flag).map(Obj::Sk),
            other => panic!("{label}: kind {other:?}"),
          };
          match obj {
            Some(obj) => (obj.status(), obj.bytes(flag), obj),
            None => (-1, Vec::new(), Obj::Empty),
          }
        }
        "pubkey" => {
          let Obj::Sk(sk) = at(step.a) else {
            panic!("{label}: operands");
          };
          let obj = Obj::Pk(public_key(sk));
          (obj.status(), obj.bytes(flag), obj)
        }
        "sign" => (0, vec_from_hex(&step.out), Obj::Sig(sig_value(&step.out, scheme))),
        "add" | "neg" | "mul" => {
          let b = step.b.map(|_| at(step.b));
          let obj = elem_op(&label, &step.op, at(step.a), b, step.k.as_deref());
          (0, obj.bytes(flag), obj)
        }
        "agg_pk" | "agg_sig" => {
          let items: Vec<&Obj> = need(step.items.as_ref(), &label, "items")
            .iter()
            .map(|&i| &regs[i].obj)
            .collect();
          match agg_op(&label, &step.op, &items, step.pair) {
            Some(obj) => (obj.status(), obj.bytes(flag), obj),
            None => (-4, Vec::new(), Obj::Empty),
          }
        }
        "dh" => {
          let recv = step.recv.map(|_| at(step.recv));
          let obj = dh_op(&label, at(step.sk), at(step.pk), recv);
          (obj.status(), obj.bytes(flag), obj)
        }
        "ser" => {
          let a = at(step.a);
          (a.status(), a.bytes(flag), Obj::Empty)
        }
        "ser_hash" => {
          let index = *need(step.a.as_ref(), &label, "operand");
          let reg = &mut regs[index];
          let bytes = reg.obj.bytes(flag);
          let hash = *reg.hash.get_or_insert_with(|| reg.obj.serialize_hash(flag));
          (reg.obj.status(), [bytes, hash.to_vec()].concat(), Obj::Empty)
        }
        "is_valid" => {
          let [wrapper, element] = is_valid_op(&label, at(step.a));
          (0, vec![u8::from(wrapper), u8::from(element)], Obj::Empty)
        }
        "eq" | "impl_eq" => {
          let eq = eq_op(&label, &step.op, at(step.a), at(step.b));
          (0, vec![u8::from(eq)], Obj::Empty)
        }
        "agg_sk" => {
          let items = need(step.items.as_ref(), &label, "items");
          let obj = Obj::Sk(aggregate_secret_keys_insecure(&sks_at(&regs, items, &label)));
          (obj.status(), obj.bytes(flag), obj)
        }
        "sub_sig" => match (at(step.a), at(step.b)) {
          (Obj::Sig(a), Obj::Sig(b)) if a.is_valid() && b.is_valid() => {
            let obj = Obj::Sig(sub_signatures_insecure(a, b));
            (obj.status(), obj.bytes(flag), obj)
          }
          (Obj::Sig(_), Obj::Sig(_)) => (-4, Vec::new(), Obj::Empty),
          _ => panic!("{label}: operands"),
        },
        "agg_secure" => {
          let sigs = sigs_at(&regs, need(step.sigs.as_deref(), &label, "sigs"), &label);
          let pks = pks_at(&regs, need(step.keys.as_deref(), &label, "keys"), &label);
          let obj = Obj::Sig(aggregate_signatures_secure(&sigs, &pks, flag));
          (obj.status(), obj.bytes(flag), obj)
        }
        "verify_sec" => {
          let Obj::Sig(sig) = at(step.sig) else {
            panic!("{label}: operands");
          };
          let pks = pks_at(&regs, need(step.keys.as_deref(), &label, "keys"), &label);
          let h = hash(need(step.msg.as_deref(), &label, "msg"));
          match verify_secure_aggregated(sig, &pks, &h, flag) {
            BlsVerdict::Unsupported => gaps += 1,
            core => assert_verdict(&label, core, None, step.status == 0),
          }
          (step.status, Vec::new(), Obj::Empty)
        }
        "sk_share" | "pk_share" | "recover_sig" => {
          let items = need(step.items.as_ref(), &label, "items");
          let recv = step.recv.map(|_| at(step.recv));
          let obj = match (step.op.as_str(), recv) {
            ("sk_share", recv) => {
              let mut out = match recv {
                Some(Obj::Sk(v)) => v.clone(),
                None => BlsSkValue::invalid(),
                _ => panic!("{label}: receiver"),
              };
              let id = hash(need(step.id.as_deref(), &label, "id"));
              let ok = secret_key_share(&mut out, &sks_at(&regs, items, &label), &id);
              assert_eq!(ok, out.is_valid(), "{label}: the receiver");
              Obj::Sk(out)
            }
            ("pk_share", recv) => {
              let mut out = match recv {
                Some(Obj::Pk(v)) => v.clone(),
                None => BlsPkValue::invalid(),
                _ => panic!("{label}: receiver"),
              };
              let id = hash(need(step.id.as_deref(), &label, "id"));
              let ok = public_key_share(&mut out, &pks_at(&regs, items, &label), &id);
              assert_eq!(ok, out.is_valid(), "{label}: the receiver");
              Obj::Pk(out)
            }
            (_, recv) => {
              let mut out = match recv {
                Some(Obj::Sig(v)) => v.clone(),
                None => BlsSigValue::invalid(),
                _ => panic!("{label}: receiver"),
              };
              let ids: Vec<[u8; 32]> = need(step.ids.as_ref(), &label, "ids").iter().map(|i| hash(i)).collect();
              let ok = recover_signature(&mut out, &sigs_at(&regs, items, &label), &ids);
              assert_eq!(ok, out.is_valid(), "{label}: the receiver");
              Obj::Sig(out)
            }
          };
          (obj.status(), obj.bytes(flag), obj)
        }
        "ies_encrypt" => {
          let Obj::Sk(eph) = at(step.sk) else {
            panic!("{label}: operands");
          };
          let seed = hash(need(step.seed.as_deref(), &label, "seed"));
          let pks = pks_at(&regs, need(step.keys.as_deref(), &label, "keys"), &label);
          let plain: Vec<Vec<u8>> = need(step.plain.as_ref(), &label, "plain")
            .iter()
            .map(|p| vec_from_hex(p))
            .collect();
          let recipients: Vec<(&BlsPkValue, &[u8])> =
            pks.iter().copied().zip(plain.iter().map(Vec::as_slice)).collect();
          let (multi, ok) = BlsIesMultiBlobs::encrypt_with(eph, &seed, &recipients);
          (i32::from(!ok), multi.to_bytes(flag), Obj::Empty)
        }
        "ies_decrypt" | "ies_decrypt_blob" => {
          let Obj::Sk(sk) = at(step.sk) else {
            panic!("{label}: operands");
          };
          let data = vec_from_hex(need(step.data.as_deref(), &label, "data"));
          let idx = *need(step.idx.as_ref(), &label, "idx");
          let mut rest = data.as_slice();
          let opened = if step.op == "ies_decrypt" {
            BlsIesMultiBlobs::decode(&mut rest, flag).map(|m| m.decrypt(idx, sk))
          } else {
            BlsIesBlobValue::decode(&mut rest, flag).map(|b| b.decrypt(idx, sk))
          };
          match opened {
            Err(_) => (-1, Vec::new(), Obj::Empty),
            Ok(_) if !rest.is_empty() => (-6, Vec::new(), Obj::Empty),
            Ok(Some(plain)) => (0, plain.to_vec(), Obj::Empty),
            Ok(None) => (1, Vec::new(), Obj::Empty),
          }
        }
        "verify" => {
          let (Obj::Sig(sig), Obj::Pk(pk)) = (at(step.sig), at(step.pk)) else {
            panic!("{label}: operands");
          };
          let h = hash(need(step.msg.as_deref(), &label, "msg"));
          let core = verify_insecure(sig, pk, &h, flag);
          let exotic = sig.point().is_some_and(|p| p.usable().is_none());
          if flag == LEGACY && exotic {
            gaps += 1;
            assert_eq!(core, BlsVerdict::Unsupported, "{label}: the relic gap closed");
          } else {
            assert_verdict(&label, core, None, step.status == 0);
          }
          (step.status, Vec::new(), Obj::Empty)
        }
        other => panic!("{label}: op {other}"),
      };
      assert_eq!(
        (step.status, step.out.as_str()),
        (status, out.to_lower_hex_string().as_str()),
        "{label}"
      );
      regs.push(made.into());
    }
  }
  gaps
}

/// The reference implementation's relic arithmetic on points outside the
/// subgroup (the BS11a design's probes P1 to P5 and its fixed vectors).
fn assert_relic() {
  assert!(assert_steps("relic") > 0, "no step in the relic gap");
}

/// Core's element operations over mixed registers (BS11a-3 D17): the shape
/// table against Exotic values and engine results, the scalar classes, the
/// aggregations, DH and its IES key, and `SER_HASH`'s cache.
fn assert_arith() {
  assert_eq!(assert_steps("arith"), 0);
}

/// Core's wrapper operations BS11b ports: secret key sums, SubInsecure,
/// AggregateSecure and its verify, threshold shares and recovery, and
/// multi-recipient IES.
fn assert_ops() {
  assert_eq!(assert_steps("ops"), 0);
}

/// Quirk 22: bytes that are canonical only under the opposite flag decode to
/// an invalid object and legacy encodings get no curve or subgroup checks;
/// every wrapper operation on such objects answers as Core's, without a gap.
#[test]
fn quirk_22_bls_opposite_scheme_and_legacy_checks() {
  assert_eq!(assert_steps("quirk22"), 0);
}

// dkg.json5

#[derive(Deserialize)]
struct Quorum {
  quorum_hash: String,
  members: Vec<Member>,
  contributions: Vec<Contribution>,
  complaints: Vec<Signed>,
  justifications: Vec<Justification>,
  member_shares: Vec<Option<MemberShare>>,
  premature: Vec<Premature>,
  #[serde(rename = "final")]
  final_: Final,
  recovered: Vec<Recovered>,
}

#[derive(Deserialize)]
struct Member {
  pro_tx: String,
  operator_sk: String,
  operator_pk: String,
}

#[derive(Deserialize)]
struct Signed {
  member: usize,
  raw: String,
  sign_hash: String,
  sig_ok: bool,
}

#[derive(Deserialize)]
struct Contribution {
  #[serde(flatten)]
  signed: Signed,
  vvec: Vec<String>,
  ies: String,
  shares: Vec<ShareRow>,
}

#[derive(Deserialize)]
struct ShareRow {
  share: Option<String>,
  fits: bool,
}

#[derive(Deserialize)]
struct Justification {
  #[serde(flatten)]
  signed: Signed,
  keys: Vec<JustifiedKey>,
}

#[derive(Deserialize)]
struct JustifiedKey {
  index: usize,
  key: String,
  fits: bool,
}

#[derive(Deserialize)]
struct MemberShare {
  sk: String,
  pk_share: String,
  fits: bool,
}

#[derive(Deserialize)]
struct Premature {
  member: usize,
  raw: String,
  commitment_hash: String,
  sig_ok: bool,
  share_ok: bool,
  matches_final: bool,
}

#[derive(Deserialize)]
struct Final {
  commitment_hash: String,
  signers: Vec<bool>,
  valid: Vec<bool>,
  quorum_pk: String,
  vvec_hash: String,
  quorum_vvec: Vec<String>,
  vvec_hash_ok: bool,
  quorum_pk_ok: bool,
  quorum_sig_ok: bool,
  members_sig_ok: bool,
  recovered_sig: String,
  members_sig_rebuilt: String,
  raw: String,
}

#[derive(Deserialize)]
struct Recovered {
  sign_hash: String,
  sig: String,
  ok: bool,
}

/// The sign hash of a contribution, complaint or justification: the
/// message with a null signature.
fn sign_hash(raw: &[u8]) -> String {
  let mut nulled = raw[..raw.len() - BLS_SIG_LEN].to_vec();
  nulled.extend_from_slice(&[0u8; BLS_SIG_LEN]);
  Sha256d::hash(&nulled).to_byte_array().to_lower_hex_string()
}

/// The last 96 bytes of a phase message, its operator signature.
fn trailing_sig(raw: &str) -> String {
  raw[raw.len() - 2 * BLS_SIG_LEN..].to_owned()
}

/// Whether a share fits a verification vector at a member's id; a share
/// that is no secret key fits nothing.
fn share_fits(vvec: &[BlsPublicKey<BlsScIetf>], id: &str, sk: &str) -> bool {
  let refs: Vec<&BlsPublicKey<BlsScIetf>> = vvec.iter().collect();
  let expect = BlsPublicKey::derive_share(&refs, &share_id(id)).unwrap_or_else(|e| panic!("{e:?}"));
  BlsSecretKey::<BlsScIetf>::from_bytes(&arr_from_hex(sk)).is_ok_and(|sk| sk.public_key() == expect)
}

/// `VerifyInsecure` under the basic scheme, the DKG's, against Core's verdict.
fn assert_dkg_sig(label: &str, sig: &str, pk: &str, h: &[u8; 32], ok: bool) {
  let core = verify_insecure(&sig_value(sig, BASIC), &pk_value(pk, BASIC), h, BASIC);
  assert_verdict(label, core, None, ok);
}

/// A regtest DKG (feature_llmq_dkgerrors.py) replayed: every signature,
/// decrypted share, aggregated vector and recovered signature as Core
/// computed it.
fn assert_dkg() {
  type S = BlsScIetf;
  let c = corpus("dkg");
  assert_eq!(c.value::<String>("scheme"), "basic");
  let quorums: Vec<Quorum> = c.vectors("quorums");
  for q in &quorums {
    let label = &q.quorum_hash[..8];
    let op_pks: Vec<String> = q.members.iter().map(|m| m.operator_pk.clone()).collect();
    for m in &q.members {
      assert_eq!(
        typed_sk::<S>(&m.operator_sk)
          .public_key()
          .to_bytes()
          .as_hex()
          .to_string(),
        m.operator_pk
      );
    }
    let check_signed = |s: &Signed, what: &str| {
      let raw = vec_from_hex(&s.raw);
      assert_eq!(sign_hash(&raw), s.sign_hash, "{label}: {what} sign hash");
      let label = format!("{label}: {what} of member {}", s.member);
      assert_dkg_sig(
        &label,
        &trailing_sig(&s.raw),
        &op_pks[s.member],
        &hash(&s.sign_hash),
        s.sig_ok,
      );
    };

    let mut vvecs = BTreeMap::new();
    for c in &q.contributions {
      check_signed(&c.signed, "contribution");
      let multi: BlsIesMulti<S> = decode_bytes::<BlsIesMultiBytes<S>>(&c.ies)
        .try_into()
        .unwrap_or_else(|e| panic!("{e:?}"));
      let vvec = typed_pks::<S>(&c.vvec);
      for (j, share) in c.shares.iter().enumerate() {
        let got = typed_sk::<S>(&q.members[j].operator_sk)
          .ies_decrypt_multi(&multi, j)
          .ok()
          .map(|p| p.to_lower_hex_string());
        assert_eq!(got, share.share, "{label}: share {} -> {j}", c.signed.member);
        if let Some(sk) = &share.share {
          assert_eq!(share_fits(&vvec, &q.members[j].pro_tx, sk), share.fits);
        }
      }
      vvecs.insert(c.signed.member, vvec);
    }
    for s in &q.complaints {
      check_signed(s, "complaint");
    }
    for j in &q.justifications {
      check_signed(&j.signed, "justification");
      for key in &j.keys {
        let fits = vvecs
          .get(&j.signed.member)
          .is_some_and(|v| share_fits(v, &q.members[key.index].pro_tx, &key.key));
        assert_eq!(fits, key.fits, "{label}: justified key for {}", key.index);
      }
    }

    // The quorum's verification vector and each member's share of it.
    let f = &q.final_;
    let qvvec = typed_pks::<S>(&f.quorum_vvec);
    let mut ser = vec![u8::try_from(qvvec.len()).unwrap_or_else(|_| panic!("vvec size"))];
    for pk in &qvvec {
      ser.extend_from_slice(&pk.to_bytes());
    }
    assert_eq!(
      Sha256d::hash(&ser).to_byte_array().to_lower_hex_string() == f.vvec_hash,
      f.vvec_hash_ok
    );
    let qvvec_values = read_all(&f.quorum_vvec, BASIC, pk_value);
    let core = serialize_hash_vector(&qvvec_values, BASIC).to_lendian();
    assert_eq!(
      core.to_lower_hex_string() == f.vvec_hash,
      f.vvec_hash_ok,
      "bls::core vvec hash"
    );
    assert_eq!(qvvec[0].to_bytes().to_lower_hex_string() == f.quorum_pk, f.quorum_pk_ok);
    // BuildQuorumVerificationVector: the valid members' vectors summed.
    for (k, want) in qvvec.iter().enumerate() {
      let parts: Vec<&BlsPublicKey<S>> = vvecs.iter().filter(|(i, _)| f.valid[**i]).map(|(_, v)| &v[k]).collect();
      assert_eq!(
        BlsPublicKey::aggregate(&parts).ok().as_ref(),
        Some(want),
        "{label}: vvec[{k}]"
      );
    }
    let qrefs: Vec<&BlsPublicKey<S>> = qvvec.iter().collect();
    for (j, share) in q.member_shares.iter().enumerate() {
      let Some(share) = share else { continue };
      let pk = BlsPublicKey::derive_share(&qrefs, &share_id(&q.members[j].pro_tx)).unwrap_or_else(|e| panic!("{e:?}"));
      assert_eq!(pk.to_bytes().to_lower_hex_string(), share.pk_share);
      assert_eq!(share_fits(&qvvec, &q.members[j].pro_tx, &share.sk), share.fits);
    }

    // The premature commitments and the final commitment's signatures.
    let mut by_member = BTreeMap::new();
    for p in &q.premature {
      let quorum_sig = &p.raw[p.raw.len() - 4 * BLS_SIG_LEN..p.raw.len() - 2 * BLS_SIG_LEN];
      let h = hash(&p.commitment_hash);
      let label_p = format!("{label}: premature commitment of {}", p.member);
      assert_dkg_sig(&label_p, &trailing_sig(&p.raw), &op_pks[p.member], &h, p.sig_ok);
      let share_pk = BlsPublicKey::derive_share(&qrefs, &share_id(&q.members[p.member].pro_tx))
        .unwrap_or_else(|e| panic!("{e:?}"))
        .to_bytes()
        .as_hex()
        .to_string();
      let label = format!("{label}: threshold share of {}", p.member);
      assert_dkg_sig(&label, quorum_sig, &share_pk, &h, p.share_ok);
      assert_eq!(p.commitment_hash == f.commitment_hash, p.matches_final);
      if p.matches_final {
        by_member.insert(p.member, (quorum_sig.to_owned(), trailing_sig(&p.raw)));
      }
    }
    let chash = hash(&f.commitment_hash);
    let fraw = &f.raw;
    let quorum_sig = &fraw[fraw.len() - 4 * BLS_SIG_LEN..fraw.len() - 2 * BLS_SIG_LEN];
    let members_sig = trailing_sig(fraw);
    assert_dkg_sig(
      &format!("{label}: quorum signature"),
      quorum_sig,
      &f.quorum_pk,
      &chash,
      f.quorum_sig_ok,
    );

    let signers: Vec<usize> = f
      .signers
      .iter()
      .enumerate()
      .filter(|(_, &s)| s)
      .map(|(i, _)| i)
      .collect();
    let spks: Vec<BlsPkValue> = signers.iter().map(|&i| pk_value(&op_pks[i], BASIC)).collect();
    let core = verify_secure_aggregated(
      &sig_value(&members_sig, BASIC),
      &spks.iter().collect::<Vec<_>>(),
      &chash,
      BASIC,
    );
    assert_verdict(&format!("{label}: members' signature"), core, None, f.members_sig_ok);

    let shares: Vec<BlsSigShare<S>> = signers
      .iter()
      .map(|&i| {
        BlsSigShare::new(
          share_id(&q.members[i].pro_tx),
          typed_sigs::<S>(&[by_member[&i].0.clone()]).remove(0),
        )
      })
      .collect();
    let recovered =
      BlsSignature::recover_shares(&shares.iter().collect::<Vec<_>>()).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
      recovered.to_bytes().to_lower_hex_string(),
      f.recovered_sig,
      "{label}: Recover"
    );
    let msigs: Vec<BlsSignature<S>> = signers
      .iter()
      .map(|&i| typed_sigs::<S>(&[by_member[&i].1.clone()]).remove(0))
      .collect();
    let mpks: Vec<BlsPublicKey<S>> = signers
      .iter()
      .map(|&i| typed_pks::<S>(&[op_pks[i].clone()]).remove(0))
      .collect();
    let rebuilt = BlsSignature::secure_aggregate(&msigs.iter().collect::<Vec<_>>(), &mpks.iter().collect::<Vec<_>>())
      .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
      rebuilt.to_bytes().to_lower_hex_string(),
      f.members_sig_rebuilt,
      "{label}: AggregateSecure"
    );

    for r in &q.recovered {
      let label = format!("{label}: recovered signature");
      assert_dkg_sig(&label, &r.sig, &f.quorum_pk, &hash(&r.sign_hash), r.ok);
    }
  }
}

// The files and their provenance.

/// Every corpus file, each checked by its own case below (`quirk22` by
/// `quirk_22_bls_opposite_scheme_and_legacy_checks`).
const FILES: [&str; 13] = [
  "hash_to_g2",
  "sign",
  "aggregate",
  "secure",
  "threshold",
  "ies",
  "decode",
  "edge",
  "relic",
  "arith",
  "ops",
  "quirk22",
  "dkg",
];

#[rstest]
#[case::hash_to_g2(|| { assert_hash_to_g2::<BlsScChia>(LEGACY); assert_hash_to_g2::<BlsScIetf>(BASIC); })]
#[case::sign(|| { assert_sign::<BlsScChia>(LEGACY); assert_sign::<BlsScIetf>(BASIC); })]
#[case::aggregate(|| { assert_aggregate::<BlsScChia>(LEGACY); assert_aggregate::<BlsScIetf>(BASIC); })]
#[case::secure(|| { assert_secure::<BlsScChia>(LEGACY); assert_secure::<BlsScIetf>(BASIC); })]
#[case::threshold(|| { assert_threshold::<BlsScChia>(LEGACY); assert_threshold::<BlsScIetf>(BASIC); })]
#[case::ies(|| { assert_ies::<BlsScChia>(LEGACY); assert_ies::<BlsScIetf>(BASIC); })]
#[case::decode(assert_decode)]
#[case::edge(assert_edge)]
#[case::relic(assert_relic)]
#[case::arith(assert_arith)]
#[case::ops(assert_ops)]
#[case::dkg(assert_dkg)]
fn core_bls_corpus(#[case] check: fn()) {
  check();
}

/// `PROVENANCE.md` names every file in the directory, and the sha256 it
/// records is the file's.
#[test]
fn every_file_has_provenance() {
  let dir = format!("{}/corpus/{DIR}", env!("CARGO_MANIFEST_DIR"));
  let provenance = std::fs::read_to_string(format!("{dir}/PROVENANCE.md")).unwrap_or_else(|e| panic!("{e}"));
  let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| panic!("{e}"))
    .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
    .filter_map(|name| name.strip_suffix(".json5").map(str::to_owned))
    .collect();
  on_disk.sort();
  let mut listed = FILES.map(str::to_owned).to_vec();
  listed.sort();
  assert_eq!(on_disk, listed, "corpus files vs the test's list");
  for file in FILES {
    let bytes = std::fs::read(format!("{dir}/{file}.json5")).unwrap_or_else(|e| panic!("{e}"));
    let digest = Sha256::hash(&bytes).to_byte_array().to_lower_hex_string();
    let entry = format!("`{file}.json5` sha256 `{digest}`");
    assert!(provenance.contains(&entry), "PROVENANCE.md lacks: {entry}");
  }
}
