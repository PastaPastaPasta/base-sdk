//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! Streaming SHAvite-3-512 over the selected backend.

use super::backend::{self, Lane};
use crate::consts::shavite::{BLOCK, IV};
use crate::util::buffer::{Buffer, Compress};
use crate::util::impl_digest;
use crate::util::memops::{digest_from_u32_le, load_u32_le};

use digest::{FixedOutput, Output, Update};

type State = [u32; 16];

/// Counter words that enter the key schedule at each HAIFA checkpoint. The
/// last word of every checkpoint enters inverted.
static INJECTION_WORDS: [[usize; 4]; 4] = [[0, 1, 2, 3], [3, 2, 1, 0], [2, 3, 0, 1], [1, 0, 3, 2]];

/// Rotates the four words of one bundle toward the front.
#[inline(always)]
fn rotate_words(bundle: Lane) -> Lane {
  shift_words(bundle, bundle)
}

/// Takes the upper three words of `older` and the first word of `newer`.
#[inline(always)]
fn shift_words(older: Lane, newer: Lane) -> Lane {
  let (older, newer) = (older.to_array(), newer.to_array());
  Lane::new([older[1], older[2], older[3], newer[0]])
}

/// Builds the counter injection vector for one checkpoint.
#[inline(always)]
fn injection(counter: u128, checkpoint: usize) -> Lane {
  let [a, b, c, d] = INJECTION_WORDS[checkpoint].map(|index| (counter >> (32 * index)) as u32);
  Lane::new([a, b, c, !d])
}

/// Expands the next eight bundles with the AES recurrence.
///
/// `INJ` names the slot that takes the counter injection, or 8 for none.
#[inline(always)]
fn expand_aes<const INJ: usize>(window: &mut [Lane; 8], inject: Lane) {
  let mut previous = window[7];
  let mut slot = 0;
  while slot < 8 {
    let mut next = backend::round(rotate_words(window[slot]), previous);
    if slot == INJ {
      next ^= inject;
    }
    window[slot] = next;
    previous = next;
    slot += 1;
  }
}

/// Expands the next eight bundles with the xor-only recurrence.
#[inline(always)]
fn expand_linear(window: &mut [Lane; 8]) {
  let mut two_back = window[6];
  let mut one_back = window[7];
  let mut slot = 0;
  while slot < 8 {
    let next = window[slot] ^ shift_words(two_back, one_back);
    window[slot] = next;
    two_back = one_back;
    one_back = next;
    slot += 1;
  }
}

/// Runs the four AES rounds of one Feistel half, the last with a zero key.
#[inline(always)]
fn feistel<const BASE: usize>(source: Lane, window: &[Lane; 8]) -> Lane {
  let mut lane = backend::round(source ^ window[BASE], window[BASE + 1]);
  lane = backend::round(lane, window[BASE + 2]);
  lane = backend::round(lane, window[BASE + 3]);
  backend::round(lane, Lane::splat(0))
}

/// Applies both Feistel halves and the column rotation of one round.
#[inline(always)]
fn mix_round(state: &mut [Lane; 4], window: &[Lane; 8]) {
  let left = feistel::<0>(state[1], window);
  let right = feistel::<4>(state[3], window);
  state[0] ^= left;
  state[2] ^= right;
  *state = [state[3], state[0], state[1], state[2]];
}

/// Runs the SHAvite-3-512 compression function.
///
/// The key schedule recurrence only reaches eight bundles back and the rounds
/// consume bundles in order, so an eight-bundle window holds the schedule.
// Inlined at every call site, the compression runs slower, so all callers
// share one copy.
#[inline(never)]
fn compress_block(chaining_value: &mut State, msg: &[u8; BLOCK], counter: u128) {
  let mut window: [Lane; 8] = core::array::from_fn(|slot| {
    Lane::new([
      load_u32_le(msg, slot * 4),
      load_u32_le(msg, slot * 4 + 1),
      load_u32_le(msg, slot * 4 + 2),
      load_u32_le(msg, slot * 4 + 3),
    ])
  });
  let mut state: [Lane; 4] = core::array::from_fn(|column| {
    Lane::new([
      chaining_value[column * 4],
      chaining_value[column * 4 + 1],
      chaining_value[column * 4 + 2],
      chaining_value[column * 4 + 3],
    ])
  });
  let zero = Lane::splat(0);

  mix_round(&mut state, &window);
  expand_aes::<0>(&mut window, injection(counter, 0));
  mix_round(&mut state, &window);
  expand_linear(&mut window);
  mix_round(&mut state, &window);
  expand_aes::<8>(&mut window, zero);
  mix_round(&mut state, &window);
  expand_linear(&mut window);
  mix_round(&mut state, &window);
  expand_aes::<1>(&mut window, injection(counter, 1));
  mix_round(&mut state, &window);
  expand_linear(&mut window);
  mix_round(&mut state, &window);
  expand_aes::<8>(&mut window, zero);
  mix_round(&mut state, &window);
  expand_linear(&mut window);
  mix_round(&mut state, &window);
  expand_aes::<7>(&mut window, injection(counter, 2));
  mix_round(&mut state, &window);
  expand_linear(&mut window);
  mix_round(&mut state, &window);
  expand_aes::<8>(&mut window, zero);
  mix_round(&mut state, &window);
  expand_linear(&mut window);
  mix_round(&mut state, &window);
  expand_aes::<6>(&mut window, injection(counter, 3));
  mix_round(&mut state, &window);

  let mut column = 0;
  while column < 4 {
    let words = state[column].to_array();
    let mut word = 0;
    while word < 4 {
      chaining_value[column * 4 + word] ^= words[word];
      word += 1;
    }
    column += 1;
  }
}

/// Chaining value and HAIFA bit counter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  h: State,
  counter: u128,
}

impl Compress<BLOCK> for Core {
  #[inline(always)]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    self.counter = self.counter.wrapping_add(1024);
    compress_block(&mut self.h, block, self.counter);
  }
}

/// Streaming SHAvite-3-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Shavite512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Shavite512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core { h: IV, counter: 0 },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Shavite512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Shavite512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    let used = self.buffer.len();
    let total = self.core.counter.wrapping_add(used as u128 * 8);
    let h = &mut self.core.h;

    // HAIFA keys each block with the bits counted so far and a block made
    // only of padding with zero. The 128-bit count and the 16-bit digest
    // length take the last 18 bytes, so a tail past byte 109 spills over.
    let mut counter = total;
    let block = self.buffer.pad(0x80);
    if used == 0 {
      counter = 0;
    } else if used >= 110 {
      compress_block(h, block, counter);
      *block = [0u8; BLOCK];
      counter = 0;
    }
    block[110..126].copy_from_slice(&total.to_le_bytes());
    block[126..].copy_from_slice(&512u16.to_le_bytes());
    compress_block(h, block, counter);
    out.copy_from_slice(&digest_from_u32_le(h));
  }
}

impl_digest!(Shavite512, U64);

#[cfg(test)]
mod tests {
  use super::{compress_block, Shavite512, BLOCK, IV};
  use crate::tests::run_nist_kat_chunked;
  use crate::util::memops::digest_from_u32_le;

  use hex_conservative::hex;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Shavite512>("shavite");
  }

  /// One compression with distinct, nonzero values in all four counter words,
  /// which no message short enough to hash in a test reaches. The expected
  /// chaining value is the sphlib compression of this block and counter.
  #[test]
  fn compress_counter_words() {
    let msg: [u8; BLOCK] = core::array::from_fn(|i| (i * 37 + 11) as u8);
    let counter = u128::from_le_bytes(hex!("67452301efcdab8998badcfe10325476"));
    let mut chaining_value = IV;
    compress_block(&mut chaining_value, &msg, counter);
    assert_eq!(
      digest_from_u32_le(&chaining_value),
      hex!(concat!(
        "c995c5ed14062715e0214c659dd89f922ac00884d0d29db96aff75091ef2fef3",
        "2351c1cd5029fe24167c12a1312506573ccd2c644642b4134ffea9ed96d93148",
      ))
    );
  }
}
