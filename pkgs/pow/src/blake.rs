//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! Blake-512 hash function.

use crate::consts::blake::{BLOCK, CB, IV, SIGMA};
use crate::util::buffer::{Buffer, Compress};
use crate::util::impl_digest;
use crate::util::memops::load_u64_le;

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
    compress(&mut self.h, &load_message(block), self.t0, self.t1);
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
      compress(h, &load_message(block), t0, t1);
    } else {
      compress(h, &load_message(block), t0, t1);
      let mut last = [0u8; BLOCK];
      last[111] = 0x01;
      last[112..120].copy_from_slice(&th.to_be_bytes());
      last[120..].copy_from_slice(&tl.to_be_bytes());
      compress(h, &load_message(&last), 0, 0);
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
