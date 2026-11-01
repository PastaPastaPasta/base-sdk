//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Adapted from SUPERCOP (regs), written by Jean-Philippe Aumasson
//

//! Blake-512 hash function.

use crate::consts::blake::{BLOCK, CB, IV, SIGMA};
use crate::util::buffer::{Buffer, Compress};
use crate::util::memops::load_u64s_be;
use crate::util::{foreach_step, impl_digest};

use digest::{FixedOutput, Output, Update};

/// Compresses one 128-byte block into the chaining state.
///
/// `t0` and `t1` are the 128-bit bit counter after this block has been counted.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compress(h: &mut [u64; 8], m: &[u64; 16], t0: u64, t1: u64) {
  #[rustfmt::skip]
  // The working state is the chaining value, four fixed constants, and the
  // counter mixed into the last four words.
  let mut v = [
    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
    CB[0], CB[1], CB[2], CB[3],
    t0 ^ CB[4], t0 ^ CB[5], t1 ^ CB[6], t1 ^ CB[7],
  ];

  // The message-word constant is added before the `b` word so the addition
  // that waits on the previous G output is the last one in the chain.
  macro_rules! g {
    ($r:expr, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr) => {{
      const S: &[usize; 16] = &SIGMA[$r];
      v[$a] = v[$a].wrapping_add(m[S[$i]] ^ CB[S[$i + 1]]).wrapping_add(v[$b]);
      v[$d] = (v[$d] ^ v[$a]).rotate_right(32);
      v[$c] = v[$c].wrapping_add(v[$d]);
      v[$b] = (v[$b] ^ v[$c]).rotate_right(25);
      v[$a] = v[$a].wrapping_add(m[S[$i + 1]] ^ CB[S[$i]]).wrapping_add(v[$b]);
      v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
      v[$c] = v[$c].wrapping_add(v[$d]);
      v[$b] = (v[$b] ^ v[$c]).rotate_right(11);
    }};
  }

  // Each round applies G to the four columns and then to the four diagonals.
  // A literal round index lets every schedule lookup fold at compile time.
  macro_rules! round {
    ($r:expr) => {{
      g!($r, 0, 4, 8, 12, 0);
      g!($r, 1, 5, 9, 13, 2);
      g!($r, 2, 6, 10, 14, 4);
      g!($r, 3, 7, 11, 15, 6);
      g!($r, 0, 5, 10, 15, 8);
      g!($r, 1, 6, 11, 12, 10);
      g!($r, 2, 7, 8, 13, 12);
      g!($r, 3, 4, 9, 14, 14);
    }};
  }

  foreach_step!(round; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

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

/// Chaining value and the 128-bit count of bits compressed so far.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  h: [u64; 8],
  t0: u64,
  t1: u64,
}

impl Compress<BLOCK> for Core {
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    advance_counter(&mut self.t0, &mut self.t1);
    compress(&mut self.h, &load_u64s_be(block), self.t0, self.t1);
  }
}

/// Streaming Blake-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Blake512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Blake512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core { h: IV, t0: 0, t1: 0 },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Blake512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Blake512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    let remaining = self.buffer.len();
    let bit_len = (remaining as u64) * 8;
    let tl = self.core.t0.wrapping_add(bit_len);
    let th = if tl < bit_len {
      self.core.t1.wrapping_add(1)
    } else {
      self.core.t1
    };
    // A block holding message bits is counted with the total length. One
    // holding only padding is counted as zero.
    let (t0, t1) = if remaining == 0 { (0, 0) } else { (tl, th) };

    // The 0x80 terminator, the 0x01 marker and the 128-bit big-endian length
    // fit after a tail ending by byte 111. Longer tails spill into a second
    // block carrying only the marker and the length.
    let h = &mut self.core.h;
    let block = self.buffer.pad(0x80);
    if remaining <= 111 {
      block[111] |= 0x01;
      block[112..120].copy_from_slice(&th.to_be_bytes());
      block[120..].copy_from_slice(&tl.to_be_bytes());
      compress(h, &load_u64s_be(block), t0, t1);
    } else {
      compress(h, &load_u64s_be(block), t0, t1);
      let mut last = [0u8; BLOCK];
      last[111] = 0x01;
      last[112..120].copy_from_slice(&th.to_be_bytes());
      last[120..].copy_from_slice(&tl.to_be_bytes());
      compress(h, &load_u64s_be(&last), 0, 0);
    }

    for (bytes, word) in out.chunks_exact_mut(8).zip(h) {
      bytes.copy_from_slice(&word.to_be_bytes());
    }
  }
}

impl_digest!(Blake512, U64);

#[cfg(test)]
mod tests {
  use super::Blake512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Blake512>("blake");
  }
}
