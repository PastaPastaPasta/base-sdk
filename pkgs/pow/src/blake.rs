//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Blake-512 hash function.

use crate::consts::blake::{BLOCK, CB, IV, SIGMA};
use crate::util::memops::{digest_from_u64_le, load_u64_le, store_u64_le, zero_extend};

/// Compresses one 128-byte block into the chaining state.
///
/// `t0` and `t1` are the 128-bit bit counter after this block has been counted.
#[inline(always)]
fn compress(h: &mut [u64; 8], m: &[u64; 16], t0: u64, t1: u64) {
  #[rustfmt::skip]
  // The working state is the chaining value, four fixed constants, and the
  // counter mixed into the last four words.
  let mut v = [
    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
    CB[0], CB[1], CB[2], CB[3],
    t0 ^ CB[4], t0 ^ CB[5], t1 ^ CB[6], t1 ^ CB[7],
  ];

  for s in &SIGMA {
    macro_rules! g {
      ($a:expr, $b:expr, $c:expr, $d:expr, $i:expr) => {{
        v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add(m[s[$i]] ^ CB[s[$i + 1]]);
        v[$d] = (v[$d] ^ v[$a]).rotate_right(32);
        v[$c] = v[$c].wrapping_add(v[$d]);
        v[$b] = (v[$b] ^ v[$c]).rotate_right(25);
        v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add(m[s[$i + 1]] ^ CB[s[$i]]);
        v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
        v[$c] = v[$c].wrapping_add(v[$d]);
        v[$b] = (v[$b] ^ v[$c]).rotate_right(11);
      }};
    }

    g!(0, 4, 8, 12, 0);
    g!(1, 5, 9, 13, 2);
    g!(2, 6, 10, 14, 4);
    g!(3, 7, 11, 15, 6);

    // The second half of the round applies the same G function on the
    // diagonals instead of the columns.
    g!(0, 5, 10, 15, 8);
    g!(1, 6, 11, 12, 10);
    g!(2, 7, 8, 13, 12);
    g!(3, 4, 9, 14, 14);
  }

  let mut i = 0;
  while i < 8 {
    h[i] ^= v[i] ^ v[i + 8];
    i += 1;
  }
}

/// Advances the 128-bit counter by 1024 (one block worth of bits).
fn advance_counter(t0: &mut u64, t1: &mut u64) {
  *t0 = t0.wrapping_add(1024);
  if *t0 < 1024 {
    *t1 = t1.wrapping_add(1);
  }
}

/// Loads one block as sixteen message words in the byte order used by the
/// compression function.
#[inline]
fn load_message(block: &[u8]) -> [u64; 16] {
  core::array::from_fn(|i| load_u64_le(block, i).swap_bytes())
}

/// Runs the full hash and returns the internal 8-word state.
#[inline(always)]
fn hash_to_state(data: &[u8]) -> [u64; 8] {
  let mut h = IV;
  let mut t0: u64 = 0;
  let mut t1: u64 = 0;

  let (blocks, tail) = data.as_chunks::<BLOCK>();
  for block in blocks {
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &load_message(block), t0, t1);
  }

  let remaining = tail.len();
  let bit_len = (remaining as u64) * 8;
  let tl = t0.wrapping_add(bit_len);
  let th = if bit_len > 0 && tl < t0 { t1.wrapping_add(1) } else { t1 };

  if remaining == 0 {
    t0 = 0xffff_ffff_ffff_fc00;
    t1 = 0xffff_ffff_ffff_ffff;
  } else if t0 == 0 {
    t0 = 0xffff_ffff_ffff_fc00u64.wrapping_add(bit_len);
    t1 = t1.wrapping_sub(1);
  } else {
    t0 = t0.wrapping_sub(1024 - bit_len);
  }

  let mut pad: [u8; 2 * BLOCK] = zero_extend(tail);
  pad[remaining] = 0x80;

  if remaining <= 111 {
    pad[111] |= 0x01;
    store_u64_le(&mut pad, 14, th.swap_bytes());
    store_u64_le(&mut pad, 15, tl.swap_bytes());
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &load_message(&pad[..BLOCK]), t0, t1);
  } else {
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &load_message(&pad[..BLOCK]), t0, t1);

    t0 = 0xffff_ffff_ffff_fc00;
    t1 = 0xffff_ffff_ffff_ffff;
    let mut fin = [0u8; BLOCK];
    fin[111] = 0x01;
    store_u64_le(&mut fin, 14, th.swap_bytes());
    store_u64_le(&mut fin, 15, tl.swap_bytes());
    advance_counter(&mut t0, &mut t1);
    compress(&mut h, &load_message(&fin), t0, t1);
  }

  h
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  digest_from_u64_le(&hash_to_state(data).map(u64::swap_bytes))
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("blake", hash512);
  }
}
