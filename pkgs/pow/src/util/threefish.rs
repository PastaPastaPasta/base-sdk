//
// Copyright (c) 2016-2017, Christian Barcenas, Artyom Pavlov
// Copyright (c) 2016-2025, The RustCrypto Project developers
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from `threefish`, a crate from `RustCrypto/block-ciphers`
//

//! Threefish-512 tweakable block cipher.
//!
//! Used as the core permutation in Skein-512. Runs 72 rounds with key injection
//! every 4 rounds (19 injections total).

/// Key schedule parity constant (C240).
const PARITY: u64 = 0x1bd11bdaa9fc1a22;

/// Number of rounds.
const ROUNDS: usize = 72;

/// Number of 64-bit words.
const NW: usize = 8;

/// Rotation constants, indexed as `ROT[round % 8][pair]`.
#[rustfmt::skip]
const ROT: [[u32; 4]; 8] = [
  [46, 36, 19, 37],
  [33, 27, 14, 42],
  [17, 49, 36, 39],
  [44,  9, 54, 56],
  [39, 30, 34, 24],
  [13, 50, 10, 17],
  [25, 29, 39, 43],
  [ 8, 35, 56, 22],
];

/// Word permutation applied after each MIX round.
const PERM: [usize; 8] = [6, 1, 0, 7, 2, 5, 4, 3];

/// Encrypts `block` in place using Threefish-512.
pub(crate) const fn encrypt(block: &mut [u64; NW], key: &[u64; NW], tweak: &[u64; 2]) {
  let mut k = [0u64; NW + 1];
  let mut i = 0;
  while i < NW {
    k[i] = key[i];
    i += 1;
  }
  k[NW] = PARITY;
  let mut i = 0;
  while i < NW {
    k[NW] ^= key[i];
    i += 1;
  }

  let t = [tweak[0], tweak[1], tweak[0] ^ tweak[1]];

  let mut d = 0;
  while d < ROUNDS {
    if d % 4 == 0 {
      let s = d / 4;
      let mut i = 0;
      while i < NW {
        block[i] = block[i].wrapping_add(k[(s + i) % (NW + 1)]);
        i += 1;
      }
      block[NW - 3] = block[NW - 3].wrapping_add(t[s % 3]);
      block[NW - 2] = block[NW - 2].wrapping_add(t[(s + 1) % 3]);
      block[NW - 1] = block[NW - 1].wrapping_add(s as u64);
    }

    let mut j = 0;
    while j < NW / 2 {
      let a = 2 * j;
      block[a] = block[a].wrapping_add(block[a + 1]);
      block[a + 1] = block[a + 1].rotate_left(ROT[d % 8][j]) ^ block[a];
      j += 1;
    }

    let prev = *block;
    let mut i = 0;
    while i < NW {
      block[PERM[i]] = prev[i];
      i += 1;
    }

    d += 1;
  }

  let s = ROUNDS / 4;
  let mut i = 0;
  while i < NW {
    block[i] = block[i].wrapping_add(k[(s + i) % (NW + 1)]);
    i += 1;
  }
  block[NW - 3] = block[NW - 3].wrapping_add(t[s % 3]);
  block[NW - 2] = block[NW - 2].wrapping_add(t[(s + 1) % 3]);
  block[NW - 1] = block[NW - 1].wrapping_add(s as u64);
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
      // Vector 1: all zeros
      Vector {
        key: [0; 8],
        pt: [0; 8],
        #[rustfmt::skip]
        ct:  words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
      },
      // Vector 2: key = vector 1 ciphertext, plaintext = zeros
      Vector {
        #[rustfmt::skip]
        key: words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
        pt: [0; 8],
        #[rustfmt::skip]
        ct:  words("f13ca06760dd9bbeab87b6c56f3bbbdbe9d08a77978b942ac02d471dc10268f2261c3d4330d6ca341f4bd4115dee16a21dcda2a34a0a76fba976174e4cf1e306"),
      },
      // Vector 3: key = vector 2 ct, pt = vector 1 ct
      Vector {
        #[rustfmt::skip]
        key: words("f13ca06760dd9bbeab87b6c56f3bbbdbe9d08a77978b942ac02d471dc10268f2261c3d4330d6ca341f4bd4115dee16a21dcda2a34a0a76fba976174e4cf1e306"),
        #[rustfmt::skip]
        pt:  words("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
        #[rustfmt::skip]
        ct:  words("1bec82cba1357566b34e1cf1fbf123a141c8f4089f6e4ce3209aea10095aec93c900d068bdc7f7a2dd58513c11dec956b93169b1c4f24cede31a265de83e36b4"),
      },
      // Vector 4: key = vec2 ct, pt = vec1 ct with last byte +1
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
    // Vectors 1-4 form a chain: each key/pt is derived from prior ct.
    let vecs = spec_vectors();
    let mut ct = [0u64; 8];

    // Vector 1: key=0, pt=0
    encrypt(&mut ct, &[0; 8], &[0; 2]);
    assert_eq!(ct, vecs[0].ct);

    // Vector 2: key=ct1, pt=0
    let key = ct;
    ct = [0; 8];
    encrypt(&mut ct, &key, &[0; 2]);
    assert_eq!(ct, vecs[1].ct);

    // Vector 3: key=ct2, pt=ct1
    let key2 = ct;
    ct = vecs[0].ct;
    encrypt(&mut ct, &key2, &[0; 2]);
    assert_eq!(ct, vecs[2].ct);
  }
}
