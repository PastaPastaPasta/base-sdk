//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar Echo-512 implementation.

use super::consts::BLOCK;
use crate::aes::{round, round_nk};
use crate::util::memops::{extract, load_u32_le, store_u32_le};

/// Increments a 128-bit counter by `val`.
const fn inc_counter(cnt: &mut [u32; 4], val: u32) {
  cnt[0] = cnt[0].wrapping_add(val);
  if cnt[0] < val {
    cnt[1] = cnt[1].wrapping_add(1);
    if cnt[1] == 0 {
      cnt[2] = cnt[2].wrapping_add(1);
      if cnt[2] == 0 {
        cnt[3] = cnt[3].wrapping_add(1);
      }
    }
  }
}

/// Increments a 128-bit counter by 1.
const fn inc_counter_one(k: &mut [u32; 4]) {
  k[0] = k[0].wrapping_add(1);
  if k[0] == 0 {
    k[1] = k[1].wrapping_add(1);
    if k[1] == 0 {
      k[2] = k[2].wrapping_add(1);
      if k[2] == 0 {
        k[3] = k[3].wrapping_add(1);
      }
    }
  }
}

/// BigSubWords: 2 AES rounds on each of 16 cells with counter key.
const fn big_sub_words(w: &mut [[u32; 4]; 16], k: &mut [u32; 4]) {
  let mut n = 0;
  while n < 16 {
    w[n] = round(&w[n], k);
    w[n] = round_nk(&w[n]);
    inc_counter_one(k);
    n += 1;
  }
}

/// BigShiftRows: row permutations on the 4x4 grid.
const fn big_shift_rows(w: &mut [[u32; 4]; 16]) {
  // Row 1: cyclic left shift by 1 across indices 1,5,9,13.
  let tmp = w[1];
  w[1] = w[5];
  w[5] = w[9];
  w[9] = w[13];
  w[13] = tmp;

  // Row 2: swap pairs (2,10) and (6,14).
  w.swap(2, 10);
  w.swap(6, 14);

  // Row 3: cyclic right shift by 1 across indices 3,7,11,15.
  let tmp = w[15];
  w[15] = w[11];
  w[11] = w[7];
  w[7] = w[3];
  w[3] = tmp;
}

/// Byte-wise xtime (multiply by 2 in GF(2^8)) on packed u32.
const fn xtime_u32(x: u32) -> u32 {
  ((x & 0x80808080) >> 7).wrapping_mul(27) ^ ((x & 0x7F7F7F7F) << 1)
}

/// BigMixColumns: GF(2^8) column mix for one column.
const fn mix_column(w: &mut [[u32; 4]; 16], ia: usize, ib: usize, ic: usize, id: usize) {
  let mut n = 0;
  while n < 4 {
    let a = w[ia][n];
    let b = w[ib][n];
    let c = w[ic][n];
    let d = w[id][n];
    let ab = a ^ b;
    let bc = b ^ c;
    let cd = c ^ d;
    let abx = xtime_u32(ab);
    let bcx = xtime_u32(bc);
    let cdx = xtime_u32(cd);
    w[ia][n] = abx ^ bc ^ d;
    w[ib][n] = bcx ^ a ^ cd;
    w[ic][n] = cdx ^ ab ^ d;
    w[id][n] = abx ^ bcx ^ cdx ^ ab ^ c;
    n += 1;
  }
}

/// BigMixColumns on all 4 columns.
const fn big_mix_columns(w: &mut [[u32; 4]; 16]) {
  mix_column(w, 0, 1, 2, 3);
  mix_column(w, 4, 5, 6, 7);
  mix_column(w, 8, 9, 10, 11);
  mix_column(w, 12, 13, 14, 15);
}

/// Echo-512 compression.
pub const fn compress(v: &mut [[u32; 4]; 8], buf: &[u8], cnt: &[u32; 4]) {
  let mut w = [[0u32; 4]; 16];

  // First 8 cells from state.
  let mut i = 0;
  while i < 8 {
    w[i] = v[i];
    i += 1;
  }

  // Next 8 cells from message buffer.
  i = 0;
  while i < 8 {
    w[i + 8][0] = load_u32_le(buf, i * 4);
    w[i + 8][1] = load_u32_le(buf, i * 4 + 1);
    w[i + 8][2] = load_u32_le(buf, i * 4 + 2);
    w[i + 8][3] = load_u32_le(buf, i * 4 + 3);
    i += 1;
  }

  // 10 big rounds.
  let mut k = *cnt;
  let mut r = 0;
  while r < 10 {
    big_sub_words(&mut w, &mut k);
    big_shift_rows(&mut w);
    big_mix_columns(&mut w);
    r += 1;
  }

  // FINAL_BIG: V[u] ^= buf_word[u] ^ W[u] ^ W[u + 8].
  i = 0;
  while i < 8 {
    let mut j = 0;
    while j < 4 {
      let buf_word = load_u32_le(buf, i * 4 + j);
      v[i][j] ^= buf_word ^ w[i][j] ^ w[i + 8][j];
      j += 1;
    }
    i += 1;
  }
}

pub const fn hash512(data: &[u8]) -> [u8; 64] {
  let mut v = [[512, 0, 0, 0]; 8];
  let mut cnt = [0u32; 4];

  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    inc_counter(&mut cnt, 1024);
    compress(&mut v, &extract::<BLOCK>(data, pos), &cnt);
    pos += BLOCK;
  }

  let ptr = data.len() - pos;
  let elen = (ptr as u32) * 8;
  inc_counter(&mut cnt, elen);

  // Save counter for padding trailer.
  let saved_cnt = cnt;

  // If no message bits in this block, zero the counter.
  if elen == 0 {
    cnt = [0; 4];
  }

  let mut buf = [0u8; BLOCK];
  if ptr > 0 {
    let mut i = 0;
    while i < ptr {
      buf[i] = data[pos + i];
      i += 1;
    }
  }
  buf[ptr] = 0x80;

  // If padding doesn't fit (ptr+1 exceeds available space).
  if ptr + 1 > BLOCK - 18 {
    compress(&mut v, &buf, &cnt);
    cnt = [0; 4];
    buf = [0u8; BLOCK];
  }

  // Output size (16-bit LE) at buf[110..112].
  let out_bits = 512u16;
  buf[BLOCK - 18] = out_bits as u8;
  buf[BLOCK - 17] = (out_bits >> 8) as u8;

  // Saved counter at buf[112..128].
  let b0 = saved_cnt[0].to_le_bytes();
  let b1 = saved_cnt[1].to_le_bytes();
  let b2 = saved_cnt[2].to_le_bytes();
  let b3 = saved_cnt[3].to_le_bytes();
  let mut ci = 0;
  while ci < 4 {
    buf[BLOCK - 16 + ci] = b0[ci];
    buf[BLOCK - 12 + ci] = b1[ci];
    buf[BLOCK - 8 + ci] = b2[ci];
    buf[BLOCK - 4 + ci] = b3[ci];
    ci += 1;
  }

  compress(&mut v, &buf, &cnt);

  // Output: first 16 u32 words from V (4 rows x 4 words).
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 4 {
    let mut j = 0;
    while j < 4 {
      store_u32_le(&mut out, i * 4 + j, v[i][j]);
      j += 1;
    }
    i += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Proves hash512 evaluates at compile time.
  const _: [u8; 64] = hash512(b"");
}
