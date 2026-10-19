//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block buffer holding the unprocessed tail of a message.

use core::fmt;
use core::hash::{Hash, Hasher};

/// Hash state that absorbs one `N`-byte block at a time.
pub(crate) trait Compress<const N: usize> {
  fn compress(&mut self, block: &[u8; N]);
}

/// At most one block of message bytes waiting for the rest of their block.
#[derive(Clone, Copy)]
pub(crate) struct Buffer<const N: usize> {
  block: [u8; N],
  len: usize,
}

impl<const N: usize> Buffer<N> {
  pub(crate) const fn new() -> Self {
    Self { block: [0; N], len: 0 }
  }

  pub(crate) const fn len(&self) -> usize {
    self.len
  }

  /// Bytes past `len` are left over from earlier blocks, so only the
  /// buffered bytes take part in equality, hashing and formatting.
  fn bytes(&self) -> &[u8] {
    &self.block[..self.len]
  }

  /// Feeds `data`, compressing each block as it completes.
  ///
  /// Blocks lying whole in `data` are compressed from `data` itself; only the
  /// partial tail is copied.
  #[inline(always)]
  pub(crate) fn update<C: Compress<N>>(&mut self, mut data: &[u8], core: &mut C) {
    if self.len > 0 {
      let take = (N - self.len).min(data.len());
      self.block[self.len..self.len + take].copy_from_slice(&data[..take]);
      self.len += take;
      data = &data[take..];
      if self.len < N {
        return;
      }
      core.compress(&self.block);
      self.len = 0;
    }
    let (blocks, tail) = data.as_chunks::<N>();
    for block in blocks {
      core.compress(block);
    }
    self.block[..tail.len()].copy_from_slice(tail);
    self.len = tail.len();
  }

  /// Feeds `data` but keeps a completed block until more data follows.
  ///
  /// For hashes that flag the last block instead of appending one, the block
  /// in the buffer is only known not to be last once a byte follows it.
  #[inline(always)]
  pub(crate) fn update_lagging<C: Compress<N>>(&mut self, mut data: &[u8], core: &mut C) {
    if data.is_empty() {
      return;
    }
    if self.len > 0 {
      if self.len < N {
        let take = (N - self.len).min(data.len());
        self.block[self.len..self.len + take].copy_from_slice(&data[..take]);
        self.len += take;
        data = &data[take..];
        if data.is_empty() {
          return;
        }
      }
      core.compress(&self.block);
      self.len = 0;
    }
    // Every block that ends before the last byte of `data` has data after it.
    let (blocks, _) = data[..data.len() - 1].as_chunks::<N>();
    for block in blocks {
      core.compress(block);
    }
    let tail = &data[blocks.len() * N..];
    self.block[..tail.len()].copy_from_slice(tail);
    self.len = tail.len();
  }

  /// Writes `marker` after the buffered bytes, zeroes the rest and returns
  /// the block for the caller to fill in the length fields.
  ///
  /// # Panics
  ///
  /// Panics if the buffered bytes fill the block.
  #[inline(always)]
  pub(crate) fn pad(&mut self, marker: u8) -> &mut [u8; N] {
    self.fill_tail(marker);
    &mut self.block
  }

  /// The buffered bytes followed by zeroes up to the block size.
  #[inline(always)]
  pub(crate) fn zero_padded(&mut self) -> &[u8; N] {
    if self.len < N {
      self.fill_tail(0);
    }
    &self.block
  }

  /// Overwrites the bytes past `len` with `marker` then zeroes.
  ///
  /// Whole 64-bit word stores let the compiler fold them into the word loads
  /// of the compression function. Byte stores would stall store forwarding.
  #[inline(always)]
  fn fill_tail(&mut self, marker: u8) {
    const { assert!(N.is_multiple_of(8)) }
    let words = self.block.as_chunks_mut::<8>().0;
    let index = self.len / 8;
    let shift = (self.len % 8) * 8;
    let kept = u64::from_le_bytes(words[index]) & ((1u64 << shift) - 1);
    words[index] = (kept | (u64::from(marker) << shift)).to_le_bytes();
    for word in &mut words[index + 1..] {
      *word = [0; 8];
    }
  }
}

impl<const N: usize> PartialEq for Buffer<N> {
  fn eq(&self, other: &Self) -> bool {
    self.bytes() == other.bytes()
  }
}

impl<const N: usize> Eq for Buffer<N> {}

impl<const N: usize> Hash for Buffer<N> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.bytes().hash(state);
  }
}

impl<const N: usize> fmt::Debug for Buffer<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Buffer").field("bytes", &self.bytes()).finish()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Records up to eight blocks handed to it.
  struct Log<const N: usize> {
    blocks: [[u8; N]; 8],
    len: usize,
  }

  impl<const N: usize> Log<N> {
    const fn new() -> Self {
      Self {
        blocks: [[0; N]; 8],
        len: 0,
      }
    }

    fn blocks(&self) -> &[[u8; N]] {
      &self.blocks[..self.len]
    }
  }

  impl<const N: usize> Compress<N> for Log<N> {
    fn compress(&mut self, block: &[u8; N]) {
      self.blocks[self.len] = *block;
      self.len += 1;
    }
  }

  /// The longest message the tests feed, a byte ramp.
  const RAMP: [u8; 100] = {
    let mut ramp = [0u8; 100];
    let mut i = 0;
    while i < 100 {
      ramp[i] = i as u8;
      i += 1;
    }
    ramp
  };

  /// Cut positions for feeding a message byte by byte.
  const BYTE_CUTS: [usize; 100] = {
    let mut cuts = [0usize; 100];
    let mut i = 0;
    while i < 100 {
      cuts[i] = i;
      i += 1;
    }
    cuts
  };

  /// Feeds `data` to a fresh buffer in the pieces `cuts` delimit.
  fn feed<const N: usize>(data: &[u8], cuts: &[usize]) -> (Log<N>, Buffer<N>) {
    let mut buffer = Buffer::<N>::new();
    let mut log = Log::new();
    let mut start = 0;
    for &cut in cuts.iter().chain(core::iter::once(&data.len())) {
      buffer.update(&data[start..cut], &mut log);
      start = cut;
    }
    (log, buffer)
  }

  /// Buffers holding the same bytes are equal whatever blocks passed
  /// through them before.
  #[test]
  fn equality_ignores_spent_blocks() {
    let (_, whole) = feed::<16>(&RAMP[..20], &[]);
    let (_, split) = feed::<16>(&RAMP[..20], &[10]);
    assert_eq!(whole, split);
  }

  /// Every chunking yields the message's whole blocks in order, then the
  /// tail.
  #[test]
  fn chunking_is_invisible() {
    for len in 0..=RAMP.len() {
      let data = &RAMP[..len];
      let expected = data.as_chunks::<16>().0;
      let check = |cuts: &[usize]| {
        let (log, buffer) = feed::<16>(data, cuts);
        assert_eq!(log.blocks(), expected, "len {len} cuts {cuts:?}");
        assert_eq!(&buffer.block[..buffer.len], &data[expected.len() * 16..]);
      };
      for first in 0..=len {
        for second in first..=len {
          check(&[first, second]);
        }
      }
      check(&BYTE_CUTS[1..len.max(1)]);
    }
  }

  /// Feeds `data` to a fresh lagging buffer in the pieces `cuts` delimit.
  fn feed_lagging<const N: usize>(data: &[u8], cuts: &[usize]) -> (Log<N>, Buffer<N>) {
    let mut buffer = Buffer::<N>::new();
    let mut log = Log::new();
    let mut start = 0;
    for &cut in cuts.iter().chain(core::iter::once(&data.len())) {
      buffer.update_lagging(&data[start..cut], &mut log);
      start = cut;
    }
    (log, buffer)
  }

  /// The lagging variant holds a complete last block back, whatever the
  /// chunking.
  #[test]
  fn lagging_holds_the_last_block() {
    for len in 0..=RAMP.len() {
      let data = &RAMP[..len];
      let whole = data.as_chunks::<16>().0;
      let held = usize::from(len > 0 && len % 16 == 0);
      let expected = &whole[..whole.len() - held];
      let check = |cuts: &[usize]| {
        let (log, buffer) = feed_lagging::<16>(data, cuts);
        assert_eq!(log.blocks(), expected, "len {len} cuts {cuts:?}");
        assert_eq!(&buffer.block[..buffer.len], &data[expected.len() * 16..]);
      };
      for first in 0..=len {
        for second in first..=len {
          check(&[first, second]);
        }
      }
      check(&BYTE_CUTS[1..len.max(1)]);
    }
  }

  /// Padding places the marker after the tail and zeroes stale bytes.
  #[test]
  fn pad_clears_stale_bytes() {
    let mut buffer = Buffer::<8>::new();
    let mut log = Log::new();
    buffer.update(&[0xAA; 7], &mut log);
    buffer.update(&[0xBB; 4], &mut log);
    assert_eq!(buffer.len(), 3);
    assert_eq!(*buffer.pad(0x80), [0xBB, 0xBB, 0xBB, 0x80, 0, 0, 0, 0]);
    assert_eq!(log.blocks(), [[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB]]);
  }

  /// Zero padding clears stale bytes and leaves a full block alone.
  #[test]
  fn zero_padding_clears_stale_bytes() {
    let mut buffer = Buffer::<8>::new();
    let mut log = Log::new();
    buffer.update(&[0xAA; 7], &mut log);
    buffer.update(&[0xBB; 4], &mut log);
    assert_eq!(*buffer.zero_padded(), [0xBB, 0xBB, 0xBB, 0, 0, 0, 0, 0]);
    buffer.update_lagging(&[0xCC; 5], &mut log);
    assert_eq!(buffer.len(), 8);
    assert_eq!(*buffer.zero_padded(), [0xBB, 0xBB, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
  }
}
