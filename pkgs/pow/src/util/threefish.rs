//
// Copyright (c) 2016-2017, Christian Barcenas, Artyom Pavlov
// Copyright (c) 2016-2025, The RustCrypto Project developers
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from `threefish`, a crate from `RustCrypto/block-ciphers`
// Adapted from SUPERCOP (opt), written by Doug Whiting
//

//! Threefish-512 tweakable block cipher.
//!
//! Used as the core permutation in Skein-512. Runs 72 rounds with key injection
//! every 4 rounds (19 injections total).

use crate::util::foreach_step;

/// Key schedule parity constant C240 (Skein 1.3 Section 8.3).
const PARITY: u64 = 0x1bd11bdaa9fc1a22;

/// Number of 64-bit words.
const NW: usize = 8;

/// Rotation constants, indexed as `ROT[round % 8][pair]`.
#[rustfmt::skip]
static ROT: [[u32; 4]; 8] = [
  [46, 36, 19, 37],
  [33, 27, 14, 42],
  [17, 49, 36, 39],
  [44,  9, 54, 56],
  [39, 30, 34, 24],
  [13, 50, 10, 17],
  [25, 29, 39, 43],
  [ 8, 35, 56, 22],
];

/// Rotates left by a compile-time amount.
#[cfg_attr(not(debug_assertions), inline(always))]
const fn rotl<const R: u32>(x: u64) -> u64 {
  x.rotate_left(R)
}

/// Encrypts `block` in place using Threefish-512.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) const fn encrypt(block: &mut [u64; NW], key: &[u64; NW], tweak: &[u64; 2]) {
  let k = [
    key[0],
    key[1],
    key[2],
    key[3],
    key[4],
    key[5],
    key[6],
    key[7],
    PARITY ^ key[0] ^ key[1] ^ key[2] ^ key[3] ^ key[4] ^ key[5] ^ key[6] ^ key[7],
  ];
  let t = [tweak[0], tweak[1], tweak[0] ^ tweak[1]];
  let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7] = *block;

  macro_rules! mix {
    ($a:ident, $b:ident, $r:expr) => {
      let rotated = rotl::<{ $r }>($b);
      $a = $a.wrapping_add($b);
      $b = rotated ^ $a;
    };
  }

  // The word permutation has period 4, so every injection lands on `x0`
  // through `x7` in order.
  macro_rules! inject {
    ($s:expr) => {
      x0 = x0.wrapping_add(k[$s % 9]);
      x1 = x1.wrapping_add(k[($s + 1) % 9]);
      x2 = x2.wrapping_add(k[($s + 2) % 9]);
      x3 = x3.wrapping_add(k[($s + 3) % 9]);
      x4 = x4.wrapping_add(k[($s + 4) % 9]);
      x5 = x5.wrapping_add(k[($s + 5) % 9]).wrapping_add(t[$s % 3]);
      x6 = x6.wrapping_add(k[($s + 6) % 9]).wrapping_add(t[($s + 1) % 3]);
      x7 = x7.wrapping_add(k[($s + 7) % 9]).wrapping_add($s as u64);
    };
  }

  macro_rules! four_rounds {
    ($s:expr) => {
      inject!($s);
      mix!(x0, x1, ROT[($s % 2) * 4][0]);
      mix!(x2, x3, ROT[($s % 2) * 4][1]);
      mix!(x4, x5, ROT[($s % 2) * 4][2]);
      mix!(x6, x7, ROT[($s % 2) * 4][3]);
      mix!(x2, x1, ROT[($s % 2) * 4 + 1][0]);
      mix!(x4, x7, ROT[($s % 2) * 4 + 1][1]);
      mix!(x6, x5, ROT[($s % 2) * 4 + 1][2]);
      mix!(x0, x3, ROT[($s % 2) * 4 + 1][3]);
      mix!(x4, x1, ROT[($s % 2) * 4 + 2][0]);
      mix!(x6, x3, ROT[($s % 2) * 4 + 2][1]);
      mix!(x0, x5, ROT[($s % 2) * 4 + 2][2]);
      mix!(x2, x7, ROT[($s % 2) * 4 + 2][3]);
      mix!(x6, x1, ROT[($s % 2) * 4 + 3][0]);
      mix!(x0, x7, ROT[($s % 2) * 4 + 3][1]);
      mix!(x2, x5, ROT[($s % 2) * 4 + 3][2]);
      mix!(x4, x3, ROT[($s % 2) * 4 + 3][3]);
    };
  }

  foreach_step!(four_rounds; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17);
  inject!(18);

  *block = [x0, x1, x2, x3, x4, x5, x6, x7];
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::util::memops::load_u64_le;

  struct Vector {
    key: [u64; 8],
    pt: [u64; 8],
    ct: [u64; 8],
  }

  /// Loads 8 little-endian u64s from a 64-byte hex string.
  fn words(hex: &str) -> [u64; 8] {
    let bytes = crate::util::from_hex(hex);
    core::array::from_fn(|i| load_u64_le(bytes.as_ref(), i))
  }

  /// Test vectors from the Threefish specification. All use zero tweak.
  fn spec_vectors() -> [Vector; 4] {
    [
      // Vector 1, all zeros
      Vector {
        key: [0; 8],
        pt: [0; 8],
        #[rustfmt::skip]
        ct:  words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
      },
      // Vector 2, key = vector 1 ciphertext, plaintext = zeros
      Vector {
        #[rustfmt::skip]
        key: words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
        pt: [0; 8],
        #[rustfmt::skip]
        ct:  words("f13ca06760dd9bbeab87b6c56f3bbbdbe9d08a77978b942ac02d471dc10268f2261c3d4330d6ca341f4bd4115dee16a21dcda2a34a0a76fba976174e4cf1e306"),
      },
      // Vector 3, key = vector 2 ct, pt = vector 1 ct
      Vector {
        #[rustfmt::skip]
        key: words("f13ca06760dd9bbeab87b6c56f3bbbdbe9d08a77978b942ac02d471dc10268f2261c3d4330d6ca341f4bd4115dee16a21dcda2a34a0a76fba976174e4cf1e306"),
        #[rustfmt::skip]
        pt:  words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
        #[rustfmt::skip]
        ct:  words("1bec82cba1357566b34e1cf1fbf123a141c8f4089f6e4ce3209aea10095aec93c900d068bdc7f7a2dd58513c11dec956b93169b1c4f24cede31a265de83e36b4"),
      },
      // Vector 4, key = vec2 ct, pt = vec1 ct with last byte +1
      Vector {
        #[rustfmt::skip]
        key: words("f13ca06760dd9bbeab87b6c56f3bbbdbe9d08a77978b942ac02d471dc10268f2261c3d4330d6ca341f4bd4115dee16a21dcda2a34a0a76fba976174e4cf1e306"),
        #[rustfmt::skip]
        pt:  words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbf"),
        #[rustfmt::skip]
        ct:  words("073cb5f8fabfa17db751477f294eb3dd4acd92b78397331fcc36a9c3d3055b81d867cbdd56279037373359ca1832669af4b87a1f2fdaf8d36e2fb7a6d19f5d45"),
      },
    ]
  }

  #[test]
  fn test_encrypt() {
    for (i, v) in spec_vectors().iter().enumerate() {
      let mut block = v.pt;
      encrypt(&mut block, &v.key, &[0; 2]);
      assert_eq!(block, v.ct, "vector {i}: encrypt mismatch");
    }
  }

  #[test]
  fn test_encrypt_chained() {
    // Vectors 1-4 form a chain, each key and pt derived from a prior ct.
    let vecs = spec_vectors();
    let mut ct = [0u64; 8];

    // Vector 1, key=0, pt=0
    encrypt(&mut ct, &[0; 8], &[0; 2]);
    assert_eq!(ct, vecs[0].ct);

    // Vector 2, key=ct1, pt=0
    let key = ct;
    ct = [0; 8];
    encrypt(&mut ct, &key, &[0; 2]);
    assert_eq!(ct, vecs[1].ct);

    // Vector 3, key=ct2, pt=ct1
    let key2 = ct;
    ct = vecs[0].ct;
    encrypt(&mut ct, &key2, &[0; 2]);
    assert_eq!(ct, vecs[2].ct);
  }
}
