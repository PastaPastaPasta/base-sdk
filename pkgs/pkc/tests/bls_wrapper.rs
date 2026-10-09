//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's BLS wrapper vectors, run against the eager and lazy types.

#![cfg(feature = "bls")]
#![expect(clippy::panic, reason = "test code")]

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
use dash_pkc::bls::{
  BlsCtx, BlsEager, BlsEagerPk, BlsEagerSig, BlsEagerSk, BlsGlobal, BlsLazy, BlsLazyPk, BlsLazySig, BlsPoint,
  BlsSchemeKind, BlsSchemeSource, BlsValue, BlsWire, BlsWirePoint, Fr, BLS_PK_LEN, BLS_SIG_LEN, BLS_SK_LEN, G1, G2,
};
use hex_conservative::DisplayHex;
use rstest::rstest;
use serde::Deserialize;

use std::collections::BTreeMap;
use std::sync::Barrier;

const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

/// One input with Core's outcome under each flag, `T`, `I` or `V:<hex>`, and
/// under `SetBytes(basic)`, `I`, `V` or `V:<legacy hex>/<basic hex>`.
#[derive(Deserialize)]
struct EagerRow {
  class: String,
  #[serde(rename = "in")]
  input: String,
  #[serde(rename = "L")]
  legacy: String,
  #[serde(rename = "B")]
  basic: String,
  #[serde(rename = "SB")]
  set_basic: String,
}

impl EagerRow {
  fn outcome(&self, scheme: BlsSchemeKind) -> &str {
    match scheme {
      BlsSchemeKind::Legacy => &self.legacy,
      BlsSchemeKind::Basic => &self.basic,
    }
  }
}

/// Two lazy objects, the ops run on each, then Core's `operator==`.
#[derive(Deserialize)]
struct PairRow {
  a: (String, String),
  b: (String, String),
  ab: (bool, String, String),
  ba: (bool, String, String),
}

fn corpus(kind: &str) -> Corpus {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_wrapper").scope(kind)
}

fn eager_rows(kind: &str) -> Vec<EagerRow> {
  corpus(kind).vectors("eager")
}

fn scheme(flag: &str) -> BlsSchemeKind {
  match flag {
    "L" => LEGACY,
    "B" => BASIC,
    _ => panic!("bad scheme flag {flag}"),
  }
}

/// The outcome of decoding `input` under `scheme`, in the corpus notation.
///
/// Also checks that a valid object serializes as its input and an invalid one
/// as zeros, under the decode scheme.
fn eager_outcome<K: BlsWire<N>, const N: usize>(input: &[u8; N], scheme: BlsSchemeKind) -> String {
  let Ok(eager) = BlsEager::<K, N>::decode(input, BlsSchemeSource::Version(scheme)) else {
    return "T".into();
  };
  assert_eq!(eager.scheme(), scheme);
  if !eager.is_valid() {
    assert_eq!(eager.to_bytes(scheme), [0u8; N]);
    assert_eq!(eager.to_bytes(scheme.opposite()), [0u8; N]);
    return "I".into();
  }
  assert_eq!(&eager.to_bytes(scheme), input, "valid object must round-trip");
  format!("V:{}", eager.to_bytes(scheme.opposite()).as_hex())
}

/// The outcome of Core's `SetBytes(input, false)`, in the corpus notation.
fn set_basic_outcome<K: BlsWire<N>, const N: usize>(input: &[u8; N]) -> String {
  let value = BlsValue::<K, N>::from_set_bytes_basic(input);
  if !value.is_valid() {
    assert_eq!(value, BlsValue::invalid());
    return "I".into();
  }
  let canonical = BlsValue::from_canonical(input, BASIC);
  if canonical.as_ref() == Some(&value) {
    assert_eq!(&value.to_bytes(BASIC), input);
    return "V".into();
  }
  let (legacy, basic) = (value.to_bytes(LEGACY), value.to_bytes(BASIC));
  format!("V:{}/{}", legacy.as_hex(), basic.as_hex())
}

/// Checks one input under both flags, the outcome and, for a valid object, its
/// serialization under the other scheme. Then checks `SetBytes(basic)`.
fn assert_eager_row<K: BlsWire<N>, const N: usize>(kind: &str, row: &EagerRow) {
  let input: [u8; N] = arr_from_hex(&row.input);
  let label = [kind, &row.class, &row.input].join(" ");
  for scheme in [LEGACY, BASIC] {
    let got = eager_outcome::<K, N>(&input, scheme);
    assert_eq!(got, row.outcome(scheme), "{label} under {scheme:?}");
  }
  let got = set_basic_outcome::<K, N>(&input);
  assert_eq!(got, row.set_basic, "{label} under SetBytes(basic)");
}

fn assert_eager_vectors<K: BlsWire<N>, const N: usize>(kind: &str) {
  for row in eager_rows(kind) {
    assert_eager_row::<K, N>(kind, &row);
  }
}

/// Eager BLS decode outcomes, Core's four-step `Unserialize`.
#[rstest]
#[case::pk(|| assert_eager_vectors::<G1, BLS_PK_LEN>("pk"))]
#[case::sig(|| assert_eager_vectors::<G2, BLS_SIG_LEN>("sig"))]
#[case::sk(|| assert_eager_vectors::<Fr, BLS_SK_LEN>("sk"))]
fn eager_bls_decode_outcomes(#[case] check: fn()) {
  check();
}

/// The outcome of reading `input` as a field under Core's process-wide flag,
/// holding `scheme`, in the corpus notation.
///
/// Decoding takes no flag, so a throw is the outcome under both. A valid
/// object written back under the flag gives the input, and written under the
/// other flag gives the bytes the notation records.
fn global_outcome<K: BlsWirePoint<N>, const N: usize>(input: &[u8; N], scheme: BlsSchemeKind) -> String {
  let Ok(global) = BlsGlobal::<K, N>::decode(input) else {
    return "T".into();
  };
  assert_eq!(&global.to_bytes(), input, "the field keeps its wire bytes");
  let ctx = BlsCtx::new(scheme);
  let eager = global.get(ctx);
  assert_eq!(eager.scheme(), scheme);
  let other = BlsGlobal::from_eager(&eager, BlsCtx::new(scheme.opposite())).to_bytes();
  if !eager.is_valid() {
    assert_eq!(other, [0u8; N]);
    return "I".into();
  }
  assert_eq!(
    &BlsGlobal::from_eager(&eager, ctx).to_bytes(),
    input,
    "valid object must round-trip"
  );
  format!("V:{}", other.as_hex())
}

fn assert_global_vectors<K: BlsWirePoint<N>, const N: usize>(kind: &str) {
  for row in eager_rows(kind) {
    let input: [u8; N] = arr_from_hex(&row.input);
    let label = [kind, &row.class, &row.input].join(" ");
    for scheme in [LEGACY, BASIC] {
      let got = global_outcome::<K, N>(&input, scheme);
      assert_eq!(got, row.outcome(scheme), "{label} under {scheme:?}");
    }
  }
}

/// A field under the process-wide flag decodes without it and gives Core's
/// eager outcome under each flag, as Core's throw does not depend on the
/// flag.
#[rstest]
#[case::pk(|| assert_global_vectors::<G1, BLS_PK_LEN>("pk"))]
#[case::sig(|| assert_global_vectors::<G2, BLS_SIG_LEN>("sig"))]
fn global_bls_fields_decode_without_the_flag(#[case] check: fn()) {
  check();
}

/// Asserts one row of the outcome table. For every sample of each class, the
/// outcome letter under each flag is one of those allowed, both in Core's
/// record and from the decoder.
fn assert_row<K: BlsWire<N>, const N: usize>(kind: &str, classes: &[&str], legacy: &str, basic: &str) {
  let rows = eager_rows(kind);
  for class in classes {
    let samples: Vec<&EagerRow> = rows.iter().filter(|row| row.class == *class).collect();
    assert!(!samples.is_empty(), "{kind}: no samples of {class}");
    for row in samples {
      let input: [u8; N] = arr_from_hex(&row.input);
      for (scheme, allowed) in [(LEGACY, legacy), (BASIC, basic)] {
        let core = &row.outcome(scheme)[..1];
        let ours = eager_outcome::<K, N>(&input, scheme);
        assert!(
          allowed.contains(core),
          "{kind}/{class}: Core gives {core} under {scheme:?}, row allows {allowed}"
        );
        assert!(
          allowed.contains(&ours[..1]),
          "{kind}/{class}: {ours} under {scheme:?}, row allows {allowed}"
        );
      }
    }
  }
}

/// The eager decode outcome table, row by row, with the legacy and basic
/// columns as the allowed outcome letters.
#[rstest]
#[case::all_zero(|| {
  assert_row::<G1, BLS_PK_LEN>("pk", &["zero"], "I", "I");
  assert_row::<G2, BLS_SIG_LEN>("sig", &["zero"], "I", "I");
  assert_row::<Fr, BLS_SK_LEN>("sk", &["zero"], "I", "I");
})]
#[case::identity_and_noncanonical_infinity(|| {
  assert_row::<G1, BLS_PK_LEN>("pk", &["identity", "inf_tail", "inf_sign", "inf_x"], "T", "T");
  let sig = ["identity", "inf_tail_hi", "inf_tail_lo", "inf_sign", "inf_x"];
  assert_row::<G2, BLS_SIG_LEN>("sig", &sig, "T", "T");
})]
#[case::coordinate_at_least_p(|| {
  assert_row::<G1, BLS_PK_LEN>("pk", &["x_eq_p_000", "x_ge_p_000", "x_ge_p_100", "x_ge_p_101"], "T", "T");
  let sig = ["legacy_c0_ge_p", "legacy_c1_ge_p", "basic_c1_ge_p", "basic_c0_ge_p", "basic_c0_flags"];
  assert_row::<G2, BLS_SIG_LEN>("sig", &sig, "T", "T");
})]
#[case::stray_flag_bits(|| {
  let pk = [
    "stray_001_sub", "stray_010_sub", "stray_011_sub", "stray_111_sub", "stray_001_off", "stray_010_off",
    "stray_011_off", "nonsub_101", "off_101", "x0_101",
  ];
  assert_row::<G1, BLS_PK_LEN>("pk", &pk, "T", "T");
  let sig = [
    "stray_001_sub", "stray_010_sub", "stray_011_sub", "stray_111_sub", "stray_010_legacy", "nonsub_basic_s1",
    "off_basic_s1", "realy_basic_s1", "x0_basic_s1",
  ];
  assert_row::<G2, BLS_SIG_LEN>("sig", &sig, "T", "T");
})]
#[case::g1_100_subgroup_point(|| assert_row::<G1, BLS_PK_LEN>("pk", &["sub_100"], "V", "V"))]
#[case::g1_000_on_curve(|| assert_row::<G1, BLS_PK_LEN>("pk", &["sub_000", "nonsub_000"], "V", "I"))]
#[case::g1_101_canonical_basic(|| assert_row::<G1, BLS_PK_LEN>("pk", &["sub_101"], "I", "V"))]
#[case::g1_off_curve_or_subgroup(|| {
  let pk = ["nonsub_000", "nonsub_100", "off_000", "off_100", "x0_100"];
  assert_row::<G1, BLS_PK_LEN>("pk", &pk, "V", "I");
})]
#[case::g2_legacy_canonical(|| {
  let sig = [
    "sub_legacy_s0", "sub_legacy_s1", "nonsub_legacy_s0", "nonsub_legacy_s1", "off_legacy_s0", "realy_legacy_s0",
  ];
  assert_row::<G2, BLS_SIG_LEN>("sig", &sig, "V", "I");
})]
#[case::g2_basic_canonical_sign_0(|| assert_row::<G2, BLS_SIG_LEN>("sig", &["sub_basic_s0"], "VI", "V"))]
#[case::g2_000_random(|| assert_row::<G2, BLS_SIG_LEN>("sig", &["nonsub_legacy_s0", "off_legacy_s0"], "V", "I"))]
#[case::g2_100_random(|| {
  assert_row::<G2, BLS_SIG_LEN>("sig", &["nonsub_legacy_s1"], "V", "I");
  assert_row::<G2, BLS_SIG_LEN>("sig", &["off_legacy_s1"], "T", "T");
})]
#[case::sk_equal_to_r(|| assert_row::<Fr, BLS_SK_LEN>("sk", &["r"], "I", "V"))]
#[case::sk_above_r(|| assert_row::<Fr, BLS_SK_LEN>("sk", &["r_plus_1", "max", "above_r"], "T", "T"))]
#[case::sk_below_r(|| assert_row::<Fr, BLS_SK_LEN>("sk", &["one", "r_minus_1", "below_r"], "V", "V"))]
#[case::g2_legacy_sign_with_real_y(|| assert_row::<G2, BLS_SIG_LEN>("sig", &["realy_legacy_s1"], "T", "T"))]
#[case::g2_basic_sign_0_not_a_point(|| {
  let sig = ["nonsub_basic_s0", "off_basic_s0", "realy_basic_s0"];
  assert_row::<G2, BLS_SIG_LEN>("sig", &sig, "VT", "IT");
})]
#[case::g2_x_zero(|| {
  assert_row::<G2, BLS_SIG_LEN>("sig", &["x0_legacy_s1", "x0_basic_s0", "x0_basic_s1"], "T", "T");
})]
fn outcome_table(#[case] check: fn()) {
  check();
}

/// A legacy decode keeps a point outside the subgroup, or off the curve, as
/// `Exotic`; every basic decode is usable.
fn assert_point_classes<K: BlsWire<N, Point = BlsPoint<A>>, A, const N: usize>(kind: &str, usable: &[&str]) {
  for row in eager_rows(kind) {
    let input: [u8; N] = arr_from_hex(&row.input);
    for scheme in [LEGACY, BASIC] {
      let Ok(eager) = BlsEager::<K, N>::decode(&input, BlsSchemeSource::Version(scheme)) else {
        continue;
      };
      let Some(point) = eager.value().point() else {
        continue;
      };
      let expect_usable = scheme == BASIC || usable.contains(&row.class.as_str());
      assert_eq!(
        point.usable().is_some(),
        expect_usable,
        "{kind}/{} under {scheme:?}",
        row.class
      );
    }
  }
}

#[rstest]
#[case::pk(|| assert_point_classes::<G1, _, BLS_PK_LEN>("pk", &["sub_000", "sub_100", "sub_000_basic"]))]
#[case::sig(|| assert_point_classes::<G2, _, BLS_SIG_LEN>("sig", &["sub_legacy_s0", "sub_legacy_s1"]))]
fn legacy_points_off_the_subgroup_are_exotic(#[case] check: fn()) {
  check();
}

/// Core's `SetBytes` resets all-zero bytes before decoding, so no scheme
/// reads them as an element; under legacy, `x = 0` would otherwise decode.
#[rstest]
#[case::legacy(LEGACY)]
#[case::basic(BASIC)]
fn zero_bytes_are_never_canonical(#[case] scheme: BlsSchemeKind) {
  assert!(BlsValue::<G1, BLS_PK_LEN>::from_canonical(&[0u8; BLS_PK_LEN], scheme).is_none());
  assert!(BlsValue::<G2, BLS_SIG_LEN>::from_canonical(&[0u8; BLS_SIG_LEN], scheme).is_none());
  assert!(BlsValue::<Fr, BLS_SK_LEN>::from_canonical(&[0u8; BLS_SK_LEN], scheme).is_none());
}

/// Core's `SetBytes` resets bytes of the wrong length to the invalid object.
#[test]
fn set_bytes_basic_needs_the_exact_length() {
  for (kind, class) in [("pk", "sub_100"), ("sig", "sub_basic_s0"), ("sk", "one")] {
    let input = vec_from_hex(&first_rows(kind)[class].input);
    let check = |bytes: &[u8]| match kind {
      "pk" => BlsValue::<G1, BLS_PK_LEN>::from_set_bytes_basic(bytes).is_valid(),
      "sig" => BlsValue::<G2, BLS_SIG_LEN>::from_set_bytes_basic(bytes).is_valid(),
      _ => BlsValue::<Fr, BLS_SK_LEN>::from_set_bytes_basic(bytes).is_valid(),
    };
    assert!(check(&input), "{kind}/{class}");
    assert!(!check(&input[1..]), "{kind}/{class} short");
    assert!(!check(&[input.as_slice(), &[0]].concat()), "{kind}/{class} long");
  }
}

/// A failed `get` turns the raw bytes into zeros for serialization, hashing
/// and equality with the default object.
#[test]
fn failed_get_zeroes_the_lazy_object() {
  let input = pk_input("sub_000");
  let lazy = BlsLazyPk::from_bytes(&input, BlsSchemeSource::Version(BASIC));
  assert_eq!(lazy.to_bytes(), input);
  assert_eq!(lazy.serialize_hash().as_bytes(), &Sha256d::hash(&input).to_byte_array());
  assert_ne!(lazy, BlsLazyPk::new(BASIC));

  assert!(!lazy.get().is_valid());
  assert_eq!(lazy.to_bytes(), [0u8; BLS_PK_LEN]);
  assert_eq!(
    lazy.serialize_hash().as_bytes(),
    &Sha256d::hash(&[0u8; BLS_PK_LEN]).to_byte_array()
  );
  assert_eq!(lazy, BlsLazyPk::new(BASIC));
}

/// The scheme alone decides the outcome, whichever rule picked it.
#[test]
fn sources_selecting_one_scheme_decode_alike() {
  for row in eager_rows("pk") {
    let input: [u8; BLS_PK_LEN] = arr_from_hex(&row.input);
    for (ctx, scheme) in [(BlsCtx::LEGACY, LEGACY), (BlsCtx::BASIC, BASIC)] {
      let by_version = BlsEagerPk::decode(&input, BlsSchemeSource::Version(scheme));
      let by_global = BlsEagerPk::decode(&input, BlsSchemeSource::Global(ctx));
      assert_eq!(by_version, by_global);
    }
    let always = BlsEagerPk::decode(&input, BlsSchemeSource::AlwaysBasic);
    assert_eq!(
      always,
      BlsEagerPk::decode(&input, BlsSchemeSource::Global(BlsCtx::BASIC))
    );
  }
}

#[test]
fn secret_keys_are_redacted() {
  for row in eager_rows("sk") {
    let input: [u8; BLS_SK_LEN] = arr_from_hex(&row.input);
    if let Ok(sk) = BlsEagerSk::decode(&input, BlsSchemeSource::AlwaysBasic) {
      assert!(!format!("{sk:?}").contains(&row.input[1..]), "{} leaks", row.class);
    }
  }
}

/// Names for the byte strings a lazy object can produce, from Core's eager
/// outcomes for its input. They are `raw`, `zero`, and `XY` for the object the
/// decode under X yields, serialized under Y.
fn tag_table(row: &EagerRow) -> BTreeMap<String, Vec<u8>> {
  let raw = vec_from_hex(&row.input);
  let mut table = BTreeMap::from([
    ("zero".to_string(), vec![0u8; raw.len()]),
    ("raw".to_string(), raw.clone()),
  ]);
  for (x, outcome) in [("L", &row.legacy), ("B", &row.basic)] {
    if let Some(other) = outcome.strip_prefix("V:") {
      let y = if x == "L" { "B" } else { "L" };
      table.insert(format!("{x}{x}"), raw.clone());
      table.insert(format!("{x}{y}"), vec_from_hex(other));
    }
  }
  table
}

fn resolve(tag: &str, table: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
  table.get(tag).cloned().unwrap_or_else(|| vec_from_hex(tag))
}

/// Builds a lazy object from its first op.
fn construct<K: BlsWirePoint<N>, const N: usize>(input: &[u8; N], op: &str) -> BlsLazy<K, N> {
  let (name, arg) = op.split_once(':').unwrap_or_else(|| panic!("bad constructor {op}"));
  match name {
    "unser" => BlsLazy::from_bytes(input, BlsSchemeSource::Version(scheme(arg))),
    "new" => BlsLazy::new(scheme(arg)),
    "set" => {
      let (x, y) = arg.split_at(1);
      let value = BlsValue::from_canonical(input, scheme(x)).unwrap_or_else(BlsValue::invalid);
      BlsLazy::from_value(value, scheme(y))
    }
    _ => panic!("bad constructor {op}"),
  }
}

/// The first eager row of each class, the input the lazy entries use.
fn first_rows(kind: &str) -> BTreeMap<String, EagerRow> {
  let mut out = BTreeMap::new();
  for row in eager_rows(kind) {
    out.entry(row.class.clone()).or_insert(row);
  }
  out
}

/// The public key the lazy entries use for `class`.
fn pk_input(class: &str) -> [u8; BLS_PK_LEN] {
  arr_from_hex(&first_rows("pk")[class].input)
}

fn prepare<K: BlsWirePoint<N>, const N: usize>(input: &[u8; N], ops: &str) -> BlsLazy<K, N> {
  let ops: Vec<&str> = ops.split(',').collect();
  let lazy = construct::<K, N>(input, ops[0]);
  for op in &ops[1..] {
    match *op {
      "get" => drop(lazy.get()),
      _ => panic!("bad pair op {op}"),
    }
  }
  lazy
}

fn assert_lazy_pairs<K: BlsWirePoint<N>, const N: usize>(kind: &str) {
  let firsts = first_rows(kind);
  let rows: Vec<PairRow> = corpus(kind).vectors("pairs");
  for row in rows {
    let (a_row, b_row) = (&firsts[&row.a.0], &firsts[&row.b.0]);
    let (a_in, b_in): ([u8; N], [u8; N]) = (arr_from_hex(&a_row.input), arr_from_hex(&b_row.input));
    let (a_table, b_table) = (tag_table(a_row), tag_table(b_row));
    for (order, (eq, a_ser, b_ser)) in [("ab", &row.ab), ("ba", &row.ba)] {
      let a = prepare::<K, N>(&a_in, &row.a.1);
      let b = prepare::<K, N>(&b_in, &row.b.1);
      let at = format!("{kind} {:?} {:?} {order}", row.a, row.b);
      let (lhs, rhs) = if order == "ab" { (&a, &b) } else { (&b, &a) };
      assert_eq!(lhs == rhs, *eq, "{at}");
      assert_eq!(a.to_bytes().to_vec(), resolve(a_ser, &a_table), "{at}, a afterwards");
      assert_eq!(b.to_bytes().to_vec(), resolve(b_ser, &b_table), "{at}, b afterwards");
    }
  }
}

/// Core's lazy `operator==`, including the `Get()` calls it makes.
#[rstest]
#[case::pk(|| assert_lazy_pairs::<G1, BLS_PK_LEN>("pk"))]
#[case::sig(|| assert_lazy_pairs::<G2, BLS_SIG_LEN>("sig"))]
fn lazy_equality_follows_core(#[case] check: fn()) {
  check();
}

#[test]
fn wrapper_fields_are_shareable() {
  fn shareable<T: Send + Sync>() {}
  shareable::<BlsLazyPk>();
  shareable::<BlsLazySig>();
  shareable::<BlsEagerPk>();
  shareable::<BlsEagerSig>();
  shareable::<BlsEagerSk>();
  shareable::<BlsValue<G1, BLS_PK_LEN>>();
}

/// Comparisons in both orders from two threads take the locks in one order.
#[test]
fn concurrent_lazy_comparisons_finish() {
  let a = BlsLazyPk::from_bytes(&pk_input("sub_000"), BlsSchemeSource::Version(LEGACY));
  let b = BlsLazyPk::from_bytes(&pk_input("sub_100"), BlsSchemeSource::Version(BASIC));
  std::thread::scope(|s| {
    let forward = s.spawn(|| (0..2000).filter(|_| a == b).count());
    let backward = s.spawn(|| (0..2000).filter(|_| b == a).count());
    let (Ok(forward), Ok(backward)) = (forward.join(), backward.join()) else {
      panic!("a comparison thread panicked");
    };
    assert_eq!(forward, backward);
  });
}

/// The signature the lazy entries use for `class`.
fn sig_input(class: &str) -> [u8; BLS_SIG_LEN] {
  arr_from_hex(&first_rows("sig")[class].input)
}

/// Joins a scoped thread, failing the test if it panicked.
fn joined<T>(handle: std::thread::ScopedJoinHandle<'_, T>) -> T {
  handle.join().unwrap_or_else(|_| panic!("a test thread panicked"))
}

/// Threads contending for one lazy signature's first decode all get the same
/// object and see consistent bytes and hashes throughout.
#[test]
fn contended_lazy_gets_agree() {
  const THREADS: usize = 8;
  let input = sig_input("sub_basic_s0");
  let want = BlsValue::from_canonical(&input, BASIC).unwrap_or_else(|| panic!("sub_basic_s0 must decode"));
  let hash = Sha256d::hash(&input).to_byte_array();
  for _ in 0..50 {
    let lazy = BlsLazySig::from_bytes(&input, BlsSchemeSource::Version(BASIC));
    let barrier = Barrier::new(THREADS);
    let values: Vec<BlsValue<G2, BLS_SIG_LEN>> = std::thread::scope(|s| {
      let handles: Vec<_> = (0..THREADS)
        .map(|i| {
          let (lazy, barrier) = (&lazy, &barrier);
          s.spawn(move || {
            barrier.wait();
            // Half the threads read before decoding, racing the others.
            if i % 2 == 0 {
              assert_eq!(lazy.to_bytes(), input);
              assert_eq!(lazy.serialize_hash().as_bytes(), &hash);
            }
            let value = lazy.get();
            assert_eq!(lazy.to_bytes(), input);
            assert!(*lazy == lazy.clone());
            value
          })
        })
        .collect();
      handles.into_iter().map(joined).collect()
    });
    assert!(values.iter().all(|value| *value == want));
    assert_eq!(lazy.serialize_hash().as_bytes(), &hash);
  }
}

/// A large differential sample from `contrib/vectors/bls_wrapper/gen.py fuzz`,
/// read from the file `BLS_WRAPPER_FUZZ` names.
#[test]
#[ignore = "needs BLS_WRAPPER_FUZZ, a file generated against Dash Core"]
fn generated_differential_sample() {
  #[derive(Deserialize)]
  struct FuzzRow {
    kind: String,
    #[serde(flatten)]
    row: EagerRow,
  }

  let path = std::env::var("BLS_WRAPPER_FUZZ").unwrap_or_else(|e| panic!("BLS_WRAPPER_FUZZ: {e}"));
  let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
  let mut checked = 0usize;
  for line in text.lines() {
    let FuzzRow { kind, row } = dash_dev::from_json(line);
    match kind.as_str() {
      "pk" => assert_eager_row::<G1, BLS_PK_LEN>(&kind, &row),
      "sig" => assert_eager_row::<G2, BLS_SIG_LEN>(&kind, &row),
      "sk" => assert_eager_row::<Fr, BLS_SK_LEN>(&kind, &row),
      _ => panic!("bad kind {kind}"),
    }
    checked += 1;
  }
  println!("checked {checked} inputs under both flags");
}
