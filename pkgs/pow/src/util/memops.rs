//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Load, store and (un)pack operations.

/// Reads a little-endian `u32` from `buf` at byte offset `i * 4`.
#[inline]
pub(crate) const fn load_u32_le(buf: &[u8], i: usize) -> u32 {
  let off = i * 4;
  u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Reads a little-endian `u64` from `buf` at byte offset `i * 8`.
#[inline]
pub(crate) const fn load_u64_le(buf: &[u8], i: usize) -> u64 {
  let off = i * 8;
  u64::from_le_bytes([
    buf[off],
    buf[off + 1],
    buf[off + 2],
    buf[off + 3],
    buf[off + 4],
    buf[off + 5],
    buf[off + 6],
    buf[off + 7],
  ])
}

/// Reads a big-endian `u64` from `buf` at byte offset `i * 8`.
#[inline]
pub(crate) const fn load_u64_be(buf: &[u8], i: usize) -> u64 {
  let off = i * 8;
  u64::from_be_bytes([
    buf[off],
    buf[off + 1],
    buf[off + 2],
    buf[off + 3],
    buf[off + 4],
    buf[off + 5],
    buf[off + 6],
    buf[off + 7],
  ])
}

/// Writes a little-endian `u32` into `buf` at byte offset `i * 4`.
#[inline]
pub(crate) const fn store_u32_le(buf: &mut [u8], i: usize, v: u32) {
  let off = i * 4;
  let b = v.to_le_bytes();
  buf[off] = b[0];
  buf[off + 1] = b[1];
  buf[off + 2] = b[2];
  buf[off + 3] = b[3];
}

/// Writes a little-endian `u64` into `buf` at byte offset `i * 8`.
#[inline]
pub(crate) const fn store_u64_le(buf: &mut [u8], i: usize, v: u64) {
  let off = i * 8;
  let b = v.to_le_bytes();
  buf[off] = b[0];
  buf[off + 1] = b[1];
  buf[off + 2] = b[2];
  buf[off + 3] = b[3];
  buf[off + 4] = b[4];
  buf[off + 5] = b[5];
  buf[off + 6] = b[6];
  buf[off + 7] = b[7];
}

/// Writes a big-endian `u64` into `buf` at byte offset `i * 8`.
#[inline]
pub(crate) const fn store_u64_be(buf: &mut [u8], i: usize, v: u64) {
  let off = i * 8;
  let b = v.to_be_bytes();
  buf[off] = b[0];
  buf[off + 1] = b[1];
  buf[off + 2] = b[2];
  buf[off + 3] = b[3];
  buf[off + 4] = b[4];
  buf[off + 5] = b[5];
  buf[off + 6] = b[6];
  buf[off + 7] = b[7];
}

/// Writes the first sixteen words little-endian into a digest.
#[inline]
pub(crate) fn digest_from_u32_le<const N: usize>(words: &[u32; N]) -> [u8; 64] {
  const { assert!(N >= 16) };
  let mut out = [0u8; 64];
  for (bytes, word) in out.chunks_exact_mut(4).zip(words) {
    bytes.copy_from_slice(&word.to_le_bytes());
  }
  out
}

/// Writes the first eight words little-endian into a digest.
#[inline]
pub(crate) fn digest_from_u64_le<const N: usize>(words: &[u64; N]) -> [u8; 64] {
  const { assert!(N >= 8) };
  let mut out = [0u8; 64];
  for (bytes, word) in out.chunks_exact_mut(8).zip(words) {
    bytes.copy_from_slice(&word.to_le_bytes());
  }
  out
}

/// Copies `bytes` into the start of a zeroed `N`-byte buffer.
#[inline]
pub(crate) fn zero_extend<const N: usize>(bytes: &[u8]) -> [u8; N] {
  let mut out = [0u8; N];
  out[..bytes.len()].copy_from_slice(bytes);
  out
}

/// Copies `N` bytes from `src` starting at `offset` into a fixed-size array,
/// avoiding range-based slice indexing which is not yet const-stable.
#[inline]
pub(crate) const fn extract<const N: usize>(src: &[u8], offset: usize) -> [u8; N] {
  let mut out = [0u8; N];
  let mut i = 0;
  while i < N {
    out[i] = src[offset + i];
    i += 1;
  }
  out
}

/// Packs 64 nibbles into 32 bytes, high nibble first.
#[inline]
pub(crate) const fn pack_nibbles(nib: &[u8; 64]) -> [u8; 32] {
  let mut out = [0u8; 32];
  let mut i = 0;
  while i < 32 {
    out[i] = (nib[2 * i] << 4) | nib[2 * i + 1];
    i += 1;
  }
  out
}

/// Unpacks 32 bytes into 64 nibbles, high nibble first.
#[inline]
pub(crate) const fn unpack_nibbles(bytes: &[u8; 32]) -> [u8; 64] {
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 32 {
    out[2 * i] = bytes[i] >> 4;
    out[2 * i + 1] = bytes[i] & 0xF;
    i += 1;
  }
  out
}
