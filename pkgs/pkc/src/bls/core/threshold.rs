//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Core's threshold operations on wrapper values: share derivation by
//! `Poly::Evaluate` and signature recovery by `Poly::LagrangeInterpolate`
//! (`threshold.cpp:169-248`).
//!
//! An id is the 32 bytes `CBLSId` stores, read big-endian modulo `r`
//! (`bls.cpp:29-34`, `threshold.cpp:98`); every id is valid, zero included.
//! Each function writes into `out` as Core writes into `*this`: `out` is
//! invalidated first, keeps its element when the function returns `false`,
//! and is assigned the result when it returns `true` (BS11b D3).

use super::{sk_scalar, sk_value, BlsPkElem, BlsPkValue, BlsSigElem, BlsSigValue, BlsSkValue, Fr};
use crate::prelude::*;

use ff::Field;
use zeroize::Zeroize;

/// `CBLSSecretKey::SecretKeyShare(msk, id)` (`bls.cpp:83-110`): `false`
/// for an invalid coefficient or fewer than two; otherwise the polynomial
/// `msk` at `id` by Horner's rule in Core's order, valid even when zero.
/// `id` ≡ 0 gives `msk[0]` reduced. Constant time in the coefficients.
pub fn secret_key_share(out: &mut BlsSkValue, msk: &[&BlsSkValue], id: &[u8; 32]) -> bool {
  out.invalidate();
  let Some((last, rest)) = msk.split_last() else {
    return false;
  };
  if rest.is_empty() || msk.iter().any(|sk| !sk.is_valid()) {
    return false;
  }
  let x = Fr::from_bendian_mod(id);
  let mut y = sk_scalar(last);
  for c in rest.iter().rev() {
    let mut c = sk_scalar(c);
    y = y * x + c;
    c.zeroize();
  }
  *out = sk_value(&mut y);
  true
}

/// `CBLSPublicKey::PublicKeyShare(mpk, id)` (`bls.cpp:179-206`): `false`
/// for an invalid coefficient or fewer than two; otherwise `y = c[n-1]`,
/// then `y = y * x + c[i]` for `i` from `n-2` down to 0 with `y` the first
/// operand, valid even when infinite. `id` ≡ 0 gives `mpk[0]`.
pub fn public_key_share(out: &mut BlsPkValue, mpk: &[&BlsPkValue], id: &[u8; 32]) -> bool {
  out.invalidate();
  let Some((last, rest)) = mpk.split_last() else {
    return false;
  };
  if rest.is_empty() || mpk.iter().any(|pk| !pk.is_valid()) {
    return false;
  }
  let x = Fr::from_bendian_mod(id).to_bendian();
  let y = rest.iter().rev().fold(BlsPkElem::from_impl(last), |y, c| {
    y.mul(&x).add(&BlsPkElem::from_impl(c))
  });
  *out = y.into();
  true
}

/// `CBLSSignature::Recover(sigs, ids)` (`bls.cpp:360-391`): `false` for
/// empty or unequal spans, an invalid share, fewer than two shares, a zero
/// product of the ids or two ids equal modulo `r`. Otherwise the sum from
/// the default element, in input order, of each share times Core's
/// coefficient `a / b_i`, where `a` is the product of every id and `b_i` is
/// id `i` times the product of `id_j - id_i` over `j != i`
/// (`threshold.cpp:190-248`). The result is valid even when infinite.
pub fn recover_signature(out: &mut BlsSigValue, sigs: &[&BlsSigValue], ids: &[[u8; 32]]) -> bool {
  out.invalidate();
  if sigs.is_empty() || sigs.len() != ids.len() || sigs.iter().any(|sig| !sig.is_valid()) || sigs.len() < 2 {
    return false;
  }
  let Some(deltas) = lagrange_at_zero(ids) else {
    return false;
  };
  *out = sigs
    .iter()
    .zip(deltas)
    .fold(BlsSigElem::default(), |r, (sig, delta)| {
      r.add(&BlsSigElem::from_impl(sig).mul(&delta.to_bendian()))
    })
    .into();
  true
}

/// Core's Lagrange coefficients at zero for at least two ids, `None` for a
/// zero product or a repeated id modulo `r`.
fn lagrange_at_zero(ids: &[[u8; 32]]) -> Option<Vec<Fr>> {
  let xs: Vec<Fr> = ids.iter().map(Fr::from_bendian_mod).collect();
  let a = xs.iter().fold(Fr::ONE, |a, x| a * x);
  if bool::from(a.is_zero()) {
    return None;
  }
  xs.iter()
    .enumerate()
    .map(|(i, xi)| {
      let mut b = *xi;
      for (j, xj) in xs.iter().enumerate() {
        if j != i {
          let v = *xj - xi;
          if bool::from(v.is_zero()) {
            return None;
          }
          b *= v;
        }
      }
      Some(a * b.inverse())
    })
    .collect()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::super::tests::{values, values_of};
  use super::*;
  use crate::bls::tests::{make_id, G1_OFF_SUBGROUP_CHIA, G2_OFF_SUBGROUP_CHIA, GROUP_ORDER};
  use crate::bls::{
    BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSchemeKind, BlsSecretKey, BlsShareId, BlsSigShare, BlsSignature,
  };

  use dash_types::Numeric;
  use rstest::rstest;

  const LEGACY: BlsSchemeKind = BlsSchemeKind::Legacy;
  const BASIC: BlsSchemeKind = BlsSchemeKind::Basic;

  struct Poly<S: BlsScheme> {
    msk: Vec<BlsSecretKey<S>>,
    mpk: Vec<BlsPublicKey<S>>,
    sks: Vec<BlsSkValue>,
    pks: Vec<BlsPkValue>,
  }

  fn poly<S: BlsScheme>(t: u8, kind: BlsSchemeKind) -> Poly<S> {
    let msk: Vec<BlsSecretKey<S>> = (1..=t)
      .map(|i| BlsSecretKey::<S>::from_ikm(&[i + 0x40; 32]).unwrap())
      .collect();
    let mpk: Vec<BlsPublicKey<S>> = msk.iter().map(BlsSecretKey::public_key).collect();
    let sks = msk
      .iter()
      .map(|sk| BlsSkValue::from_canonical(&sk.to_bytes(), kind).unwrap())
      .collect();
    let pks = mpk
      .iter()
      .map(|pk| BlsPkValue::from_canonical(&pk.to_bytes(), kind).unwrap())
      .collect();
    Poly { msk, mpk, sks, pks }
  }

  /// [`poly`]'s values in the scheme `kind` decodes.
  fn poly_values(t: u8, kind: BlsSchemeKind) -> (Vec<BlsSkValue>, Vec<BlsPkValue>) {
    match kind {
      LEGACY => {
        let p = poly::<BlsScChia>(t, kind);
        (p.sks, p.pks)
      }
      BASIC => {
        let p = poly::<BlsScIetf>(t, kind);
        (p.sks, p.pks)
      }
    }
  }

  fn id(i: u32) -> [u8; 32] {
    *make_id(i).as_bytes()
  }

  fn sk_share(msk: &[BlsSkValue], id: &[u8; 32]) -> Option<BlsSkValue> {
    let mut out = BlsSkValue::invalid();
    secret_key_share(&mut out, &msk.iter().collect::<Vec<_>>(), id).then_some(out)
  }

  fn pk_share(mpk: &[BlsPkValue], id: &[u8; 32]) -> Option<BlsPkValue> {
    let mut out = BlsPkValue::invalid();
    public_key_share(&mut out, &mpk.iter().collect::<Vec<_>>(), id).then_some(out)
  }

  fn recover(sigs: &[BlsSigValue], ids: &[[u8; 32]]) -> Option<BlsSigValue> {
    let mut out = BlsSigValue::invalid();
    recover_signature(&mut out, &sigs.iter().collect::<Vec<_>>(), ids).then_some(out)
  }

  fn assert_agrees_with_typed<S: BlsScheme>(kind: BlsSchemeKind) {
    let msg = [8u8; 32];
    let p = poly::<S>(3, kind);
    let msk: Vec<&BlsSecretKey<S>> = p.msk.iter().collect();
    let mpk: Vec<&BlsPublicKey<S>> = p.mpk.iter().collect();
    let ids: Vec<[u8; 32]> = (1..=5).map(id).collect();
    let mut sigs = Vec::new();
    let mut typed_shares = Vec::new();
    for x in &ids {
      let share_id = BlsShareId::from_lendian(*x);
      let typed_sk = BlsSecretKey::derive_share(&msk, &share_id).unwrap();
      let typed_pk = BlsPublicKey::derive_share(&mpk, &share_id).unwrap();
      let sk = sk_share(&p.sks, x).unwrap();
      let pk = pk_share(&p.pks, x).unwrap();
      assert_eq!(sk.to_bytes(kind), *typed_sk.to_bytes());
      assert_eq!(pk.to_bytes(kind), typed_pk.to_bytes());
      assert_eq!(typed_sk.public_key(), typed_pk);
      let sig = typed_sk.sign(S::msg_ref(&msg));
      sigs.push(BlsSigValue::from_canonical(&sig.to_bytes(), kind).unwrap());
      typed_shares.push(BlsSigShare::new(share_id, sig));
    }
    let master = p.msk[0].sign(S::msg_ref(&msg)).to_bytes();
    for range in [0..3, 2..5, 0..5, 1..4] {
      let typed = BlsSignature::recover_shares(&typed_shares[range.clone()].iter().collect::<Vec<_>>()).unwrap();
      let got = recover(&sigs[range.clone()], &ids[range]).unwrap();
      assert_eq!(got.to_bytes(kind), typed.to_bytes());
      assert_eq!(got.to_bytes(kind), master);
    }
    let short = recover(&sigs[..2], &ids[..2]).unwrap();
    assert_ne!(short.to_bytes(kind), master);
  }

  #[rstest]
  #[case::legacy(assert_agrees_with_typed::<BlsScChia>, LEGACY)]
  #[case::basic(assert_agrees_with_typed::<BlsScIetf>, BASIC)]
  fn threshold_agrees_with_the_typed_api(#[case] assertion: fn(BlsSchemeKind), #[case] kind: BlsSchemeKind) {
    assertion(kind);
  }

  /// An id that reduces to zero gives the constant term, which the typed
  /// API refuses; `r` reads as zero and `r + 1` as one.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn ids_are_read_modulo_the_order(#[case] kind: BlsSchemeKind) {
    let (sks, pks) = poly_values(3, kind);
    for zero in [[0u8; 32], GROUP_ORDER] {
      assert_eq!(sk_share(&sks, &zero).unwrap(), sks[0]);
      let pk = pk_share(&pks, &zero).unwrap();
      assert!(pk.core_eq(&pks[0]));
      assert_eq!(pk.to_bytes(kind), pks[0].to_bytes(kind));
    }
    let mut above = GROUP_ORDER;
    above[31] += 1;
    assert_eq!(sk_share(&sks, &above), sk_share(&sks, &id(1)));
    assert_eq!(pk_share(&pks, &above), pk_share(&pks, &id(1)));
  }

  /// A share can be a valid zero key or a valid infinity: with
  /// `c = (k, -k)` the polynomial vanishes at one.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn zero_and_infinite_shares_are_valid(#[case] kind: BlsSchemeKind) {
    let k = [0x22u8; 32];
    let sks = [
      BlsSkValue::from_canonical(&k, kind).unwrap(),
      BlsSkValue::from_canonical(&crate::bls::tests::negate_scalar(&k), kind).unwrap(),
    ];
    let zero = sk_share(&sks, &id(1)).unwrap();
    assert!(zero.is_valid());
    assert_eq!(zero.to_bytes(kind), [0u8; 32]);

    let (_, pk) = values_of(1, &[1; 32], kind);
    let neg: BlsPkValue = BlsPkElem::from_impl(&pk).neg().into();
    let infinity = pk_share(&[pk, neg], &id(1)).unwrap();
    assert!(infinity.is_valid());
    assert_eq!(infinity.to_bytes(kind), BlsPkValue::invalid().element(kind).0);
  }

  /// The gates: fewer than two coefficients or shares, an invalid one,
  /// unequal spans, a zero id and a repeated id modulo `r` all fail, and
  /// the receiver keeps its element, invalid.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn failures_keep_the_receivers_element(#[case] kind: BlsSchemeKind) {
    let (sks, pks) = poly_values(2, kind);
    let (sig, pk) = values_of(2, &[2; 32], kind);
    let sk = sks[0].clone();
    let (s0, s1) = (values_of(3, &[3; 32], kind).0, values_of(4, &[4; 32], kind).0);

    let mut out = sk.clone();
    assert!(!secret_key_share(&mut out, &[&sks[0]], &id(1)));
    assert!(!out.is_valid());
    assert_eq!(out.parts().0, sk.parts().0);
    let mut out = sk.clone();
    assert!(!secret_key_share(&mut out, &[], &id(1)));
    assert_eq!(out.parts().0, sk.parts().0);
    let mut out = sk.clone();
    assert!(!secret_key_share(&mut out, &[&sks[0], &BlsSkValue::invalid()], &id(1)));
    assert!(!out.is_valid());
    assert_eq!(out.parts().0, sk.parts().0);

    for mpk in [&[&pks[0]][..], &[], &[&pks[0], &BlsPkValue::invalid()]] {
      let mut out = pk.clone();
      assert!(!public_key_share(&mut out, mpk, &id(1)));
      assert!(!out.is_valid());
      assert_eq!(out.element(kind), pk.element(kind));
    }

    let mut r_plus_two = GROUP_ORDER;
    r_plus_two[31] += 2;
    let cases: [(&[&BlsSigValue], &[[u8; 32]]); 7] = [
      (&[], &[]),
      (&[&s0], &[id(1)]),
      (&[&s0, &s1], &[id(1)]),
      (&[&s0, &BlsSigValue::invalid()], &[id(1), id(2)]),
      (&[&s0, &s1], &[id(1), [0; 32]]),
      (&[&s0, &s1], &[id(1), id(1)]),
      (&[&s0, &s1], &[id(2), r_plus_two]),
    ];
    for (sigs, ids) in cases {
      let mut out = sig.clone();
      assert!(!recover_signature(&mut out, sigs, ids), "{} shares", sigs.len());
      assert!(!out.is_valid());
      assert_eq!(out.element(kind), sig.element(kind));
    }
  }

  /// On success the receiver's earlier element is replaced.
  #[rstest]
  #[case::legacy(LEGACY)]
  #[case::basic(BASIC)]
  fn success_assigns_the_receiver(#[case] kind: BlsSchemeKind) {
    let (sks, pks) = poly_values(2, kind);
    let (sig, pk) = values_of(5, &[5; 32], kind);
    let mut out = pk;
    assert!(public_key_share(&mut out, &pks.iter().collect::<Vec<_>>(), &id(3)));
    assert_eq!(Some(out), pk_share(&pks, &id(3)));
    let mut out = sks[1].clone();
    assert!(secret_key_share(&mut out, &sks.iter().collect::<Vec<_>>(), &id(3)));
    assert_eq!(Some(out), sk_share(&sks, &id(3)));
    let mut out = sig.clone();
    assert!(recover_signature(&mut out, &[&sig, &sig], &[id(1), id(2)]));
    assert_eq!(Some(out), recover(&[sig.clone(), sig], &[id(1), id(2)]));
  }

  /// The coefficients are Core's: for ids 1 and 2 they are 2 and -1, so
  /// two equal shares recover the share itself.
  #[test]
  fn coefficients_are_cores() {
    let deltas = lagrange_at_zero(&[id(1), id(2)]).unwrap();
    assert_eq!(deltas, [Fr::from(2), -Fr::ONE]);
    let (sig, _) = values::<BlsScIetf>(6, &[6; 32], BASIC);
    assert_eq!(recover(&[sig.clone(), sig.clone()], &[id(1), id(2)]), Some(sig));
  }

  /// Legacy keys and signatures outside the subgroup go through the engine
  /// in Core's operand order.
  #[test]
  fn exotic_operands_run_the_engine() {
    let exotic_pk = BlsPkValue::from_canonical(&G1_OFF_SUBGROUP_CHIA, LEGACY).unwrap();
    let exotic_sig = BlsSigValue::from_canonical(&G2_OFF_SUBGROUP_CHIA, LEGACY).unwrap();
    let (sig, pk) = values::<BlsScChia>(7, &[7; 32], LEGACY);
    let x = id(5);
    let share = pk_share(&[pk.clone(), exotic_pk.clone()], &x).unwrap();
    let want = BlsPkElem::from_impl(&exotic_pk).mul(&x).add(&BlsPkElem::from_impl(&pk));
    assert!(BlsPkElem::from_impl(&share).__is_relic());
    assert!(BlsPkElem::from_impl(&share).core_eq(&want));
    assert_eq!(share.to_bytes(LEGACY), want.to_bytes(LEGACY));

    let ids = [id(1), id(2)];
    let got = recover(&[exotic_sig.clone(), sig.clone()], &ids).unwrap();
    let deltas = lagrange_at_zero(&ids).unwrap();
    let want = BlsSigElem::default()
      .add(&BlsSigElem::from_impl(&exotic_sig).mul(&deltas[0].to_bendian()))
      .add(&BlsSigElem::from_impl(&sig).mul(&deltas[1].to_bendian()));
    assert!(BlsSigElem::from_impl(&got).__is_relic());
    assert_eq!(got.to_bytes(LEGACY), want.to_bytes(LEGACY));
  }
}
