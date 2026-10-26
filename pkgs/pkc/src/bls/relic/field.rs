//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! relic's prime-field layer as the curve functions use it, over blst's
//! serial field arithmetic.
//!
//! Both libraries hold an element in Montgomery form with R = 2^384, as six
//! 64-bit little-endian limbs, so a limb vector here is relic's `dp`. Field
//! values are exact, so only the operations whose result relic defines
//! differently from the field need code of their own: inversion of zero and
//! the batch inversion.

use super::super::scalar::{Fp, Fp2};

use blst::{blst_fp, blst_fp2};

/// An element of `Fp` from relic's Montgomery limbs.
pub(super) const fn fp(l: [u64; 6]) -> Fp {
  Fp::from_raw_limbs(l)
}

/// An element of `Fp2` from the Montgomery limbs of `c0` and `c1`.
pub(super) const fn fp2(c0: [u64; 6], c1: [u64; 6]) -> Fp2 {
  Fp2(blst_fp2 {
    fp: [blst_fp { l: c0 }, blst_fp { l: c1 }],
  })
}

/// One, relic's `fp_set_dig(a, 1)`: R mod p.
pub(super) const ONE: Fp = fp([
  0x7609_0000_0002_fffd,
  0xebf4_000b_c40c_0002,
  0x5f48_9857_53c7_58ba,
  0x77ce_5853_7052_5745,
  0x5c07_1a97_a256_ec6d,
  0x15f6_5ec3_fa80_e493,
]);

/// Three times the G1 curve constant, 3b = 12: `ctx->ep_b3`
/// (`relic_ep_curve.c`, set by `ep_curve_set_endom`), read by
/// `ep_curve_mul_b3` and `ep_curve_get_b3`.
pub(super) const B3: Fp = fp([
  0x4476_0000_0027_552e,
  0xdcb8_009a_4348_0020,
  0x6f7e_e9ce_4a6e_8b59,
  0xb103_30b7_c0a9_5bc6,
  0x6140_b1fc_fb1e_54b7,
  0x0381_be09_7f0b_b4e1,
]);

/// The cube root of unity beta of the G1 endomorphism
/// psi(x, y) = (beta x, y): `ctx->beta`, which `ep_curve_set_endom` picks
/// (`relic_ep_curve.c:445-458`).
pub(super) const BETA: Fp = fp([
  0xcd03_c9e4_8671_f071,
  0x5dab_2246_1fcd_a5d2,
  0x5870_42af_d385_1b95,
  0x8eb6_0ebe_01ba_cb9e,
  0x03f9_7d6e_83d0_50d2,
  0x18f0_2065_5463_8741,
]);

/// The Frobenius twist constants `ctx->ep2_frb[0]` and `ctx->ep2_frb[1]`,
/// xi^-(p-1)/3 and xi^-(p-1)/2 for xi = 1 + u, which `ep2_frb` multiplies into
/// x and y (`relic_ep2_frb.c:38-48`).
pub(super) const EP2_FRB: [Fp2; 2] = [
  fp2(
    [0; 6],
    [
      0x890d_c9e4_8675_45c3,
      0x2af3_2253_3285_a5d5,
      0x5088_0866_309b_7e2c,
      0xa20d_1b8c_7e88_1024,
      0x14e4_f04f_e2db_9068,
      0x14e5_6d3f_1564_853a,
    ],
  ),
  fp2(
    [
      0x3e2f_585d_a55c_9ad1,
      0x4294_213d_86c1_8183,
      0x3828_44c8_8b62_3732,
      0x92ad_2afd_1910_3e18,
      0x1d79_4e4f_ac7c_f0b9,
      0x0bd5_92fc_7d82_5ec8,
    ],
    [
      0x7bcf_a7a2_5aa3_0fda,
      0xdc17_dec1_2a92_7e7c,
      0x2f08_8dd8_6b4e_bef1,
      0xd1ca_2087_da74_d4a7,
      0x2da2_5966_96ce_bc1d,
      0x0e2b_7eed_bbfd_87d2,
    ],
  ),
];

/// The twist's curve constant b' = 4(1 + u), `ctx->ep2_b`
/// (`ep2_curve_get_b`), which the Miller loop's doubling reads.
pub(super) const TWIST_B: Fp2 = {
  let four = [
    0xaa27_0000_000c_fff3,
    0x53cc_0032_fc34_000a,
    0x478f_e97a_6b0a_807f,
    0xb1d3_7ebe_e6ba_24d7,
    0x8ec9_733b_bf78_ab2f,
    0x09d6_4551_3d83_de7e,
  ];
  fp2(four, four)
};

/// floor(p/2), big-endian, against which `ep_pck` and `ep2_pck` compare y
/// (`relic_ep_pck.c:40-58`, `relic_ep2_pck.c:40-60`).
const HALF_P: [u8; 48] = hex_conservative::hex!(
  "0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555"
);

/// Whether `a` is zero, relic's `fp_is_zero`. blst keeps elements reduced,
/// so zero has one representation.
pub(super) fn is_zero(a: &Fp) -> bool {
  a.0.l == [0; 6]
}

/// `2a`, relic's `fp_dbl`.
pub(super) fn dbl(a: Fp) -> Fp {
  a + a
}

/// relic's `fp_inv`, with `fp_inv(0) = 0` (`relic_fp_inv.c`, FP_INV LOWER).
pub(super) fn inv(a: Fp) -> Fp {
  if is_zero(&a) {
    Fp::default()
  } else {
    a.inverse()
  }
}

/// relic's `fp2_inv`: `a0²+a1²` inverted by `fp_inv`, so zero gives zero
/// (`relic_fpx_inv.c:39-90`).
pub(super) fn inv2(a: Fp2) -> Fp2 {
  if a.is_zero() {
    Fp2::default()
  } else {
    a.inverse()
  }
}

/// relic's `fp_inv_sim` (`relic_fp_inv.c:523-565`): Montgomery's batch
/// inversion. One zero zeroes the running product, so then every entry
/// comes out zero.
pub(super) fn inv_sim<const N: usize>(a: [Fp; N]) -> [Fp; N] {
  let mut c = a;
  for i in 1..N {
    c[i] = c[i - 1] * a[i];
  }
  let mut u = inv(c[N - 1]);
  for i in (1..N).rev() {
    c[i] = u * c[i - 1];
    u = u * a[i];
  }
  c[0] = u;
  c
}

/// `ep_pck`'s sign of y: whether its integer value exceeds floor(p/2).
pub(super) fn sign(y: Fp) -> bool {
  <[u8; 48]>::from(y) > HALF_P
}

/// The conjugate `c0 - c1 u`, relic's `fp2_frb(c, a, 1)`
/// (`relic_fpx_frb.c:39-50`).
pub(super) fn conj(a: Fp2) -> Fp2 {
  a.with_c1(-a.c1())
}

#[cfg(test)]
mod tests {
  use super::*;

  /// p, big-endian.
  const P: [u8; 48] = hex_conservative::hex!(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
  );

  fn pow(base: Fp2, exp: &[u8]) -> Fp2 {
    exp.iter().fold(Fp2::from(ONE), |acc, byte| {
      (0..8).rev().fold(acc, |acc, bit| {
        let sq = acc.square();
        if byte >> bit & 1 == 1 {
          sq * base
        } else {
          sq
        }
      })
    })
  }

  /// (p - 1) / d, big-endian, for d dividing p - 1.
  fn p_minus_one_over(d: u32) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut rem = 0u32;
    let mut p = P;
    p[47] -= 1;
    for (o, b) in out.iter_mut().zip(p) {
      let cur = rem << 8 | u32::from(b);
      *o = (cur / d) as u8;
      rem = cur % d;
    }
    assert_eq!(rem, 0);
    out
  }

  #[test]
  fn one_and_b3_are_montgomery_constants() {
    assert_eq!(ONE, Fp::from_u64(1));
    assert_eq!(B3, Fp::from_u64(12));
    assert_eq!(TWIST_B, Fp2::new(Fp::from_u64(4), Fp::from_u64(4)));
  }

  #[test]
  fn beta_is_a_nontrivial_cube_root_of_unity() {
    assert_ne!(BETA, ONE);
    assert_eq!(BETA * BETA * BETA, ONE);
  }

  #[test]
  fn frobenius_constants_are_powers_of_xi() {
    let xi = Fp2::new(ONE, ONE);
    assert_eq!(pow(xi, &p_minus_one_over(3)) * EP2_FRB[0], Fp2::from(ONE));
    assert_eq!(pow(xi, &p_minus_one_over(2)) * EP2_FRB[1], Fp2::from(ONE));
  }

  #[test]
  fn half_p_is_half_the_prime() {
    let mut doubled = [0u8; 48];
    let mut carry = 1u16;
    for (d, h) in doubled.iter_mut().zip(HALF_P).rev() {
      let v = u16::from(h) * 2 + carry;
      *d = v as u8;
      carry = v >> 8;
    }
    assert_eq!(doubled, P);
    assert!(!sign(fp([0; 6])));
    assert!(sign(-ONE));
    assert!(!sign(ONE));
    // The boundary: floor(p/2) itself is not above it.
    assert!(!sign(Fp::from(&HALF_P)));
    assert!(sign(Fp::from(&HALF_P) + ONE));
  }

  #[test]
  fn inversion_maps_zero_to_zero() {
    assert_eq!(inv(Fp::default()), Fp::default());
    assert_eq!(inv(B3) * B3, ONE);
    assert_eq!(inv2(Fp2::default()), Fp2::default());
    let a = Fp2::new(B3, BETA);
    assert_eq!(inv2(a) * a, Fp2::from(ONE));
  }

  #[test]
  fn batch_inversion_zeroes_every_entry_after_a_zero() {
    let two = dbl(ONE);
    assert_eq!(inv_sim([two, B3, BETA]), [inv(two), inv(B3), inv(BETA)]);
    assert_eq!(inv_sim([two, Fp::default(), BETA]), [Fp::default(); 3]);
  }

  #[test]
  fn conjugation_negates_c1() {
    let a = Fp2::new(B3, BETA);
    assert_eq!(conj(a), Fp2::new(B3, -BETA));
    assert_eq!(a * conj(a), Fp2::from(B3 * B3 + BETA * BETA));
  }
}
