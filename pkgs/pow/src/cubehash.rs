//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! CubeHash-16/32-512 hash function.

use crate::consts::cubehash::{BLOCK, IV};
use crate::util::arx::rotl_u32x4;
use crate::util::buffer::{Buffer, Compress};
use crate::util::memops::{digest_from_u32_le, load_u32_le};
use crate::util::{impl_digest, impl_hash};

use digest::{FixedOutput, Output, Update};
use wide::u32x4;

/// Four neighbouring state words packed into one group.
type U32x4 = u32x4;

#[inline]
/// Swaps the low and high 2-word halves inside one 4-word register.
fn swap_halves(words: U32x4) -> U32x4 {
  let lanes = words.to_array();
  U32x4::new([lanes[2], lanes[3], lanes[0], lanes[1]])
}

#[inline]
/// Swaps each adjacent 2-word pair inside one 4-word register.
fn swap_pairs(words: U32x4) -> U32x4 {
  let lanes = words.to_array();
  U32x4::new([lanes[1], lanes[0], lanes[3], lanes[2]])
}

#[inline]
/// Loads one 4-word register from the flat 32-word state.
fn load_vec(words: &[u32; 32], index: usize) -> U32x4 {
  let base = index * 4;
  U32x4::new([words[base], words[base + 1], words[base + 2], words[base + 3]])
}

#[inline]
/// Stores one 4-word register back into the flat 32-word state.
fn store_vec(words: &mut [u32; 32], index: usize, value: U32x4) {
  let base = index * 4;
  let lanes = value.to_array();
  words[base] = lanes[0];
  words[base + 1] = lanes[1];
  words[base + 2] = lanes[2];
  words[base + 3] = lanes[3];
}

#[inline]
/// Reads one 32-byte block as the two registers xored into state.
fn load_block(block: &[u8]) -> (U32x4, U32x4) {
  (
    U32x4::new([
      load_u32_le(block, 0),
      load_u32_le(block, 1),
      load_u32_le(block, 2),
      load_u32_le(block, 3),
    ]),
    U32x4::new([
      load_u32_le(block, 4),
      load_u32_le(block, 5),
      load_u32_le(block, 6),
      load_u32_le(block, 7),
    ]),
  )
}

/// Applies 16 CubeHash rounds.
///
/// Each round pair updates the upper half, rotates the lower half, swaps lanes,
/// then repeats with a different rotation amount.
#[cfg_attr(not(debug_assertions), inline(always))]
fn sixteen_rounds(state: &mut [U32x4; 8]) {
  // Locals keep the state in registers, whereas array slots round-trip
  // memory every round.
  let [mut s0, mut s1, mut s2, mut s3, mut s4, mut s5, mut s6, mut s7] = *state;
  let mut i = 0;
  while i < 16 {
    s4 += s0;
    s5 += s1;
    s6 += s2;
    s7 += s3;

    let next0 = rotl_u32x4(s2, 7) ^ s4;
    let next1 = rotl_u32x4(s3, 7) ^ s5;
    let next2 = rotl_u32x4(s0, 7) ^ s6;
    let next3 = rotl_u32x4(s1, 7) ^ s7;
    s0 = next0;
    s1 = next1;
    s2 = next2;
    s3 = next3;

    s4 = swap_halves(s4);
    s5 = swap_halves(s5);
    s6 = swap_halves(s6);
    s7 = swap_halves(s7);

    s4 += s0;
    s5 += s1;
    s6 += s2;
    s7 += s3;

    let next0 = rotl_u32x4(s1, 11) ^ s4;
    let next1 = rotl_u32x4(s0, 11) ^ s5;
    let next2 = rotl_u32x4(s3, 11) ^ s6;
    let next3 = rotl_u32x4(s2, 11) ^ s7;
    s0 = next0;
    s1 = next1;
    s2 = next2;
    s3 = next3;

    s4 = swap_pairs(s4);
    s5 = swap_pairs(s5);
    s6 = swap_pairs(s6);
    s7 = swap_pairs(s7);

    i += 1;
  }
  *state = [s0, s1, s2, s3, s4, s5, s6, s7];
}

/// Absorbs two word vectors into the state.
fn absorb_words(state: &mut [U32x4; 8], lo: U32x4, hi: U32x4) {
  state[0] ^= lo;
  state[1] ^= hi;
  sixteen_rounds(state);
}

/// Absorbs a 32-byte block into the state.
fn absorb_block(state: &mut [U32x4; 8], block: &[u8]) {
  let (lo, hi) = load_block(block);
  absorb_words(state, lo, hi);
}

/// The 32-word state.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Core {
  state: [U32x4; 8],
}

impl Compress<BLOCK> for Core {
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    absorb_block(&mut self.state, block);
  }
}

impl_hash!(Core, [state], []);

/// Streaming CubeHash-16/32-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CubeHash512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for CubeHash512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core {
        state: core::array::from_fn(|index| load_vec(&IV, index)),
      },
      buffer: Buffer::new(),
    }
  }
}

impl Update for CubeHash512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for CubeHash512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    self.core.compress(self.buffer.pad(0x80));

    // The finalization flag goes into word 31, the last lane of `state[7]`.
    let state = &mut self.core.state;
    state[7] ^= U32x4::new([0, 0, 0, 1]);
    let mut i = 0;
    while i < 10 {
      sixteen_rounds(state);
      i += 1;
    }

    let mut words = [0u32; 32];
    store_vec(&mut words, 0, state[0]);
    store_vec(&mut words, 1, state[1]);
    store_vec(&mut words, 2, state[2]);
    store_vec(&mut words, 3, state[3]);
    out.copy_from_slice(&digest_from_u32_le(&words));
  }
}

impl_digest!(CubeHash512, U64);

#[cfg(test)]
mod tests {
  use super::CubeHash512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<CubeHash512>("cubehash");
  }
}
