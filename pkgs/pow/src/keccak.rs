//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Keccak-512 hash function.

use crate::consts::keccak::{RATE, RC, ROTC};
use crate::util::memops::{digest_from_u64_le, zero_extend};

/// Applies one round of the permutation, reading from `src` and writing to
/// `dst`.
///
/// Each output row is computed independently with only five temporaries,
/// reducing register pressure compared to materializing all 25 B-values. State
/// layout: `a[x + 5*y]` for x, y in {0, 1, 2, 3, 4}.
#[inline(always)]
fn round_to(src: &[u64; 25], dst: &mut [u64; 25], rc: u64) {
  // theta
  let c0 = src[0] ^ src[5] ^ src[10] ^ src[15] ^ src[20];
  let c1 = src[1] ^ src[6] ^ src[11] ^ src[16] ^ src[21];
  let c2 = src[2] ^ src[7] ^ src[12] ^ src[17] ^ src[22];
  let c3 = src[3] ^ src[8] ^ src[13] ^ src[18] ^ src[23];
  let c4 = src[4] ^ src[9] ^ src[14] ^ src[19] ^ src[24];

  let d0 = c4 ^ c1.rotate_left(1);
  let d1 = c0 ^ c2.rotate_left(1);
  let d2 = c1 ^ c3.rotate_left(1);
  let d3 = c2 ^ c4.rotate_left(1);
  let d4 = c3 ^ c0.rotate_left(1);

  // theta + rho + pi + chi + iota, row by row
  // Each block: read 5 source lanes (fusing theta), apply rho+pi
  // rotations, then chi directly into dst. Only 5 B-values live at once.
  {
    let b0 = src[0] ^ d0;
    let b1 = (src[6] ^ d1).rotate_left(ROTC[6]);
    let b2 = (src[12] ^ d2).rotate_left(ROTC[12]);
    let b3 = (src[18] ^ d3).rotate_left(ROTC[18]);
    let b4 = (src[24] ^ d4).rotate_left(ROTC[24]);
    dst[0] = b0 ^ (!b1 & b2) ^ rc;
    dst[1] = b1 ^ (!b2 & b3);
    dst[2] = b2 ^ (!b3 & b4);
    dst[3] = b3 ^ (!b4 & b0);
    dst[4] = b4 ^ (!b0 & b1);
  }
  {
    let b0 = (src[3] ^ d3).rotate_left(ROTC[3]);
    let b1 = (src[9] ^ d4).rotate_left(ROTC[9]);
    let b2 = (src[10] ^ d0).rotate_left(ROTC[10]);
    let b3 = (src[16] ^ d1).rotate_left(ROTC[16]);
    let b4 = (src[22] ^ d2).rotate_left(ROTC[22]);
    dst[5] = b0 ^ (!b1 & b2);
    dst[6] = b1 ^ (!b2 & b3);
    dst[7] = b2 ^ (!b3 & b4);
    dst[8] = b3 ^ (!b4 & b0);
    dst[9] = b4 ^ (!b0 & b1);
  }
  {
    let b0 = (src[1] ^ d1).rotate_left(ROTC[1]);
    let b1 = (src[7] ^ d2).rotate_left(ROTC[7]);
    let b2 = (src[13] ^ d3).rotate_left(ROTC[13]);
    let b3 = (src[19] ^ d4).rotate_left(ROTC[19]);
    let b4 = (src[20] ^ d0).rotate_left(ROTC[20]);
    dst[10] = b0 ^ (!b1 & b2);
    dst[11] = b1 ^ (!b2 & b3);
    dst[12] = b2 ^ (!b3 & b4);
    dst[13] = b3 ^ (!b4 & b0);
    dst[14] = b4 ^ (!b0 & b1);
  }
  {
    let b0 = (src[4] ^ d4).rotate_left(ROTC[4]);
    let b1 = (src[5] ^ d0).rotate_left(ROTC[5]);
    let b2 = (src[11] ^ d1).rotate_left(ROTC[11]);
    let b3 = (src[17] ^ d2).rotate_left(ROTC[17]);
    let b4 = (src[23] ^ d3).rotate_left(ROTC[23]);
    dst[15] = b0 ^ (!b1 & b2);
    dst[16] = b1 ^ (!b2 & b3);
    dst[17] = b2 ^ (!b3 & b4);
    dst[18] = b3 ^ (!b4 & b0);
    dst[19] = b4 ^ (!b0 & b1);
  }
  {
    let b0 = (src[2] ^ d2).rotate_left(ROTC[2]);
    let b1 = (src[8] ^ d3).rotate_left(ROTC[8]);
    let b2 = (src[14] ^ d4).rotate_left(ROTC[14]);
    let b3 = (src[15] ^ d0).rotate_left(ROTC[15]);
    let b4 = (src[21] ^ d1).rotate_left(ROTC[21]);
    dst[20] = b0 ^ (!b1 & b2);
    dst[21] = b1 ^ (!b2 & b3);
    dst[22] = b2 ^ (!b3 & b4);
    dst[23] = b3 ^ (!b4 & b0);
    dst[24] = b4 ^ (!b0 & b1);
  }
}

/// Applies the permutation in place.
///
/// Two full state buffers keep the round body simple: one round reads from
/// `state`, the next reads from `alt`, and the final result ends back in
/// `state`.
#[inline(always)]
fn keccak_f1600(state: &mut [u64; 25]) {
  let mut alt = [0u64; 25];
  let mut i = 0;
  while i < 24 {
    round_to(state, &mut alt, RC[i]);
    round_to(&alt, state, RC[i + 1]);
    i += 2;
  }
}

/// Absorbs one rate-sized block into the first lanes of the state.
#[inline(always)]
fn absorb(state: &mut [u64; 25], block: &[u8; RATE]) {
  for (lane, word) in state.iter_mut().zip(block.as_chunks::<8>().0) {
    *lane ^= u64::from_le_bytes(*word);
  }
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let mut state = [0u64; 25];
  let (blocks, tail) = data.as_chunks::<RATE>();
  for block in blocks {
    absorb(&mut state, block);
    keccak_f1600(&mut state);
  }

  let mut last: [u8; RATE] = zero_extend(tail);
  last[tail.len()] = 0x01;
  last[RATE - 1] |= 0x80;
  absorb(&mut state, &last);
  keccak_f1600(&mut state);
  digest_from_u64_le(&state)
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("keccak", hash512);
  }
}
