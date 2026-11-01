//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test fixtures and constants.

use crate::prelude::*;
pub(crate) use crate::tests::bls::{make_id, sequential_ids, test_ikm, test_msg};

use cfg_if::cfg_if;
use hex_conservative::hex;

/// BLS12-381 scalar field order r, big-endian.
pub const GROUP_ORDER: [u8; 32] = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// Negate a scalar below the group order, as `order - s`.
///
/// Builds the tweak that cancels a key without going through the field code
/// under test.
pub fn negate_scalar(s: &[u8; 32]) -> [u8; 32] {
  let mut out = [0u8; 32];
  let mut borrow = 0i16;

  for i in (0..32).rev() {
    let diff = i16::from(GROUP_ORDER[i]) - i16::from(s[i]) - borrow;
    borrow = i16::from(diff < 0);
    out[i] = diff.rem_euclid(256) as u8;
  }
  out
}

/// Fixed 32-byte IKMs for deterministic test keys (all 0x00, 0x01, 0x02, 0x03).
pub const RSEED: [[u8; 32]; 4] = [[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]];

/// Test message.
pub const MSG_DEADBEEF: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

/// A message distinct from [`MSG_DEADBEEF`].
pub const MSG_8BADFOOD: [u8; 32] = hex!("8badf00d8badf00d8badf00d8badf00dfeedfacefeedfacefeedfacefeedface");

/// Smallest off-subgroup G1 point, Chia-encoded: `x = 4` is the least `x`
/// with `x^3 + 4` a residue mod `p` and `[r]P != O`.
pub const G1_OFF_SUBGROUP_CHIA: [u8; 48] =
  hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004");

/// [`G1_OFF_SUBGROUP_CHIA`] in the IETF encoding: compression bit set, sign
/// bit clear.
pub const G1_OFF_SUBGROUP_IETF: [u8; 48] =
  hex!("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004");

/// [`G1_OFF_SUBGROUP_CHIA`] with the field prime added to `x`, so the
/// coordinate is out of range while the flag bits stay untouched.
pub const G1_X_GE_PRIME_CHIA: [u8; 48] =
  hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaf");

/// The least out-of-range `x`, the field prime itself, Chia-encoded.
pub const G1_X_EQ_PRIME_CHIA: [u8; 48] =
  hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

/// The largest `x` the Chia encoding can carry, every bit below the three
/// flags set, so nothing beyond the flags is left to reinterpret.
pub const G1_X_MAX_CHIA: [u8; 48] =
  hex!("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// Smallest off-subgroup G2 point, Chia-encoded: `x.c0 = 2` is the least
/// value with `x^3 + 4(1 + u)` square in `Fp2` and `[r]P != O`.
pub const G2_OFF_SUBGROUP_CHIA: [u8; 96] = hex!(concat!(
  "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
));

/// [`G2_OFF_SUBGROUP_CHIA`] in the IETF encoding: `[x.c1, x.c0]` order,
/// compression bit and sign bit set.
pub const G2_OFF_SUBGROUP_IETF: [u8; 96] = hex!(concat!(
  "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
));

/// Re-encode a Chia G1 coordinate under the IETF compression bit.
pub const fn ietf_g1_encoding(mut chia: [u8; 48]) -> [u8; 48] {
  chia[0] |= 0x80;
  chia
}

cfg_if! {
  if #[cfg(test)] {
    use super::group::G1Affine;
    use super::scheme_ops::BlsScheme;
    use super::schemes::BlsScChia;

    use blst::BLST_ERROR;
    use dash_dev::Corpus;

    use core::fmt;

    #[derive(Debug)]
    pub enum SerType {
      Signature,
      PublicKey,
    }

    impl fmt::Display for SerType {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
          Self::Signature => "sig",
          Self::PublicKey => "pk",
        })
      }
    }

    /// Pairs each Chia encoding with the same point's IETF encoding.
    ///
    /// The two arms correspond by position, so their lengths must agree before the
    /// zip. A one-sided edit would otherwise drop the tail silently instead of
    /// failing.
    pub fn ser_pairs(kind: SerType) -> Vec<(String, String)> {
      let section = kind.to_string();
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_serialize");
      let legacy: Vec<String> = corpus.scope("chia").vectors(&section);
      let ietf: Vec<String> = corpus.scope("ietf").vectors(&section);
      assert_eq!(legacy.len(), ietf.len(), "bls_serialize: {section} arms must pair by index");
      legacy.into_iter().zip(ietf).collect()
    }

    /// The reference implementation's outcome for one `bls_read` input.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, ::serde::Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ReadOutcome {
      Null,
      Valid,
      Invalid,
    }

    /// Whether the `x` of an input the legacy scheme reads as valid has a
    /// point on the curve.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, ::serde::Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Curve {
      On,
      Off,
    }

    /// One `bls_read` input, its outcome under each scheme and, when the
    /// legacy scheme reads it as valid, whether its `x` has a curve point.
    #[derive(Debug, ::serde::Deserialize)]
    pub struct ReadVector {
      pub class: String,
      #[serde(rename = "in")]
      pub input: String,
      legacy: ReadOutcome,
      basic: ReadOutcome,
      #[serde(default)]
      pub curve: Option<Curve>,
    }

    impl ReadVector {
      pub fn outcome(&self, legacy: bool) -> ReadOutcome {
        if legacy { self.legacy } else { self.basic }
      }
    }

    /// The `bls_read` vectors of one kind.
    pub fn read_vectors(kind: SerType) -> Vec<ReadVector> {
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_read").vectors(&kind.to_string())
    }

    /// Whether the legacy G1 encoding `b` holds an `x` with no point on the
    /// curve.
    pub fn chia_pk_off_curve(b: &[u8; 48]) -> bool {
      matches!(
        G1Affine::uncompress(&BlsScChia::pk_ietf_bytes(b)),
        Err(BLST_ERROR::BLST_POINT_NOT_ON_CURVE)
      )
    }

    #[expect(clippy::unwrap_used, reason = "test code")]
    mod layouts {
      use super::*;
      use crate::bls::group::G2Affine;
      use crate::bls::schemes::BlsScIetf;

      use rstest::rstest;

      /// A point other than infinity in the scheme's layout, taken back to the
      /// IETF compressed layout, is the point's IETF encoding for G1, and its
      /// `x` with the sign bit clear for G2.
      fn assert_layouts_reach_ietf<S: BlsScheme>() {
        let mut signs = [[false; 2]; 2];
        for seed in &RSEED {
          let sk = BlsScIetf::sk_from_ikm(seed).unwrap();
          let g1 = BlsScIetf::derive_pk(&sk).compress();
          let g2 = BlsScIetf::sign(&sk, &MSG_DEADBEEF).compress();
          let point = G1Affine::uncompress(&g1).unwrap();
          assert_eq!(S::pk_ietf_bytes(&S::g1_bytes(&point)), g1);
          let point = G2Affine::uncompress(&g2).unwrap();
          let mut unsigned = g2;
          unsigned[0] &= !0x20;
          assert_eq!(S::sig_ietf_x_bytes(&S::g2_bytes(&point)), unsigned);
          signs[0][usize::from(g1[0] & 0x20 != 0)] = true;
          signs[1][usize::from(g2[0] & 0x20 != 0)] = true;
        }
        assert_eq!(signs, [[true; 2]; 2], "the seeds cover both signs");
      }

      #[rstest]
      #[case::chia(assert_layouts_reach_ietf::<BlsScChia>)]
      #[case::ietf(assert_layouts_reach_ietf::<BlsScIetf>)]
      fn layouts_reach_the_ietf_form(#[case] check: fn()) {
        check();
      }
    }

    mod builders {
      use super::*;

      use rstest::rstest;

      #[rstest]
      #[case::ikm(test_ikm)]
      #[case::msg(test_msg)]
      fn injective_past_256(#[case] build: fn(usize) -> [u8; 32]) {
        let mut built: Vec<[u8; 32]> = (0..1000).map(build).collect();
        built.sort_unstable();
        let total = built.len();
        built.dedup();
        assert_eq!(built.len(), total, "index does not survive into the output");
      }
    }
  }
}
