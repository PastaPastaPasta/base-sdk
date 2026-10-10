//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar SHAvite-3-512 implementation.

use super::consts::{BLOCK, IV};
use crate::aes::scalar::round_nk;
use crate::util::memops::{extract, load_u32_le, store_u32_le};

/// Expands 128-byte message block into 448 round keys.
const fn key_schedule(msg: &[u8], cnt: &[u32; 4]) -> [u32; 448] {
  let mut rk = [0u32; 448];
  let mut i = 0;
  while i < 32 {
    rk[i] = load_u32_le(msg, i);
    i += 1;
  }

  // AES expansion step: AES_ROUND_NOKEY then XOR with
  // rk[u-4..u-1]. Counter injected at specific offsets.
  macro_rules! aes_step {
    ($u:expr) => {{
      let x = [rk[$u - 31], rk[$u - 30], rk[$u - 29], rk[$u - 32]];
      let y = round_nk(&x);
      rk[$u] = y[0] ^ rk[$u - 4];
      rk[$u + 1] = y[1] ^ rk[$u - 3];
      rk[$u + 2] = y[2] ^ rk[$u - 2];
      rk[$u + 3] = y[3] ^ rk[$u - 1];
    }};
  }

  // Alternating AES and linear blocks (Section 3.4).
  let mut u = 32;
  loop {
    // AES block: 4 pairs of AES steps (32 words).
    let mut s = 0;
    while s < 4 {
      aes_step!(u);
      if u == 32 {
        rk[32] ^= cnt[0];
        rk[33] ^= cnt[1];
        rk[34] ^= cnt[2];
        rk[35] ^= !cnt[3];
      } else if u == 440 {
        rk[440] ^= cnt[1];
        rk[441] ^= cnt[0];
        rk[442] ^= cnt[3];
        rk[443] ^= !cnt[2];
      }
      u += 4;

      aes_step!(u);
      if u == 164 {
        rk[164] ^= cnt[3];
        rk[165] ^= cnt[2];
        rk[166] ^= cnt[1];
        rk[167] ^= !cnt[0];
      } else if u == 316 {
        rk[316] ^= cnt[2];
        rk[317] ^= cnt[3];
        rk[318] ^= cnt[0];
        rk[319] ^= !cnt[1];
      }
      u += 4;
      s += 1;
    }

    if u == 448 {
      break;
    }

    // Linear block: 8 XOR steps (32 words).
    s = 0;
    while s < 8 {
      rk[u] = rk[u - 32] ^ rk[u - 7];
      rk[u + 1] = rk[u - 31] ^ rk[u - 6];
      rk[u + 2] = rk[u - 30] ^ rk[u - 5];
      rk[u + 3] = rk[u - 29] ^ rk[u - 4];
      u += 4;
      s += 1;
    }
  }
  rk
}

/// 4 AES rounds on right half, XOR result into left half.
const fn c512_elt(p: &mut [u32; 16], l: [usize; 4], r: [usize; 4], rk: &[u32; 448], off: usize) {
  let mut x = [p[r[0]], p[r[1]], p[r[2]], p[r[3]]];
  let mut k = 0;
  while k < 4 {
    x[0] ^= rk[off + k * 4];
    x[1] ^= rk[off + k * 4 + 1];
    x[2] ^= rk[off + k * 4 + 2];
    x[3] ^= rk[off + k * 4 + 3];
    x = round_nk(&x);
    k += 1;
  }
  p[l[0]] ^= x[0];
  p[l[1]] ^= x[1];
  p[l[2]] ^= x[2];
  p[l[3]] ^= x[3];
}

/// 14-round Feistel compression.
pub const fn compress(h: &mut [u32; 16], msg: &[u8], cnt: &[u32; 4]) {
  let rk = key_schedule(msg, cnt);
  let mut p = *h;

  let mut off = 0;
  let mut r = 0;
  while r < 14 {
    c512_elt(&mut p, [0, 1, 2, 3], [4, 5, 6, 7], &rk, off);
    off += 16;
    c512_elt(&mut p, [8, 9, 10, 11], [12, 13, 14, 15], &rk, off);
    off += 16;

    // WROT: rotate each column (stride 4) right by 1.
    let mut col = 0;
    while col < 4 {
      let tmp = p[col + 12];
      p[col + 12] = p[col + 8];
      p[col + 8] = p[col + 4];
      p[col + 4] = p[col];
      p[col] = tmp;
      col += 1;
    }
    r += 1;
  }

  let mut i = 0;
  while i < 16 {
    h[i] ^= p[i];
    i += 1;
  }
}

/// Increments a 128-bit counter by `bits`.
const fn inc_counter(cnt: &mut [u32; 4], bits: u32) {
  cnt[0] = cnt[0].wrapping_add(bits);
  if cnt[0] < bits {
    cnt[1] = cnt[1].wrapping_add(1);
    if cnt[1] == 0 {
      cnt[2] = cnt[2].wrapping_add(1);
      if cnt[2] == 0 {
        cnt[3] = cnt[3].wrapping_add(1);
      }
    }
  }
}

pub const fn hash512(data: &[u8]) -> [u8; 64] {
  let mut h = IV;
  let mut cnt = [0u32; 4];

  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    inc_counter(&mut cnt, 1024);
    compress(&mut h, &extract::<BLOCK>(data, pos), &cnt);
    pos += BLOCK;
  }

  let ptr = data.len() - pos;
  inc_counter(&mut cnt, (ptr as u32) * 8);
  // Save counters before possible zeroing.
  let saved_cnt = cnt;

  let mut buf = [0u8; BLOCK];
  if ptr == 0 {
    buf[0] = 0x80;
    cnt = [0; 4];
  } else {
    let mut i = 0;
    while i < ptr {
      buf[i] = data[pos + i];
      i += 1;
    }
    if ptr < 110 {
      buf[ptr] = 0x80;
    } else {
      buf[ptr] = 0x80;
      compress(&mut h, &buf, &cnt);
      buf = [0u8; BLOCK];
      cnt = [0; 4];
    }
  }

  // Encode saved counter and output size in padding.
  // Counter at byte offsets 110, 114, 118, 122 (not u32-aligned).
  let b0 = saved_cnt[0].to_le_bytes();
  let b1 = saved_cnt[1].to_le_bytes();
  let b2 = saved_cnt[2].to_le_bytes();
  let b3 = saved_cnt[3].to_le_bytes();
  let mut ci = 0;
  while ci < 4 {
    buf[110 + ci] = b0[ci];
    buf[114 + ci] = b1[ci];
    buf[118 + ci] = b2[ci];
    buf[122 + ci] = b3[ci];
    ci += 1;
  }
  // Output size: 16 u32 words.
  buf[126] = (16u32 << 5) as u8;
  buf[127] = (16u32 >> 3) as u8;
  compress(&mut h, &buf, &cnt);

  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 16 {
    store_u32_le(&mut out, i, h[i]);
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
