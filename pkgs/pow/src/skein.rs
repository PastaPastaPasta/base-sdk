//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Skein-512 hash function.

use crate::consts::skein::{BLOCK, IV, NW};
use crate::util::memops::{load_u64_le, store_u64_le};
use crate::util::threefish::encrypt;

/// UBI type code for message blocks.
pub(super) const TYPE_MSG: u64 = 48;
/// UBI type code for output blocks.
const TYPE_OUTPUT: u64 = 63;
/// Marks the first block in one UBI stream.
const FLAG_FIRST: u64 = 1 << 62;
/// Marks the final block in one UBI stream.
const FLAG_FINAL: u64 = 1 << 63;

/// Skein chaining value, stored as eight 64-bit words.
pub type Chaining = [u64; NW];
/// One 64-byte Skein block decoded as eight little-endian words.
pub type BlockWords = [u64; NW];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UbiTweak {
  /// Total number of bytes seen so far in this UBI stream.
  pub position: u64,
  /// UBI block type, such as "message" or "output".
  pub kind: u64,
  /// Marks the first block in a UBI stream.
  pub first: bool,
  /// Marks the final block in a UBI stream.
  pub final_block: bool,
}

impl UbiTweak {
  /// Encodes the tweak in the two-word Threefish format.
  ///
  /// The low word is the running byte count. The high word stores the block
  /// type together with the first/final marker bits.
  #[inline]
  fn as_words(self) -> [u64; 2] {
    let mut t1 = self.kind << 56;
    if self.first {
      t1 |= FLAG_FIRST;
    }
    if self.final_block {
      t1 |= FLAG_FINAL;
    }
    [self.position, t1]
  }
}

/// Reads one 64-byte Skein block as eight little-endian words.
fn load_block(block: &[u8]) -> BlockWords {
  core::array::from_fn(|index| load_u64_le(block, index))
}

/// Applies one UBI step.
///
/// UBI uses Threefish with the current chaining value as the key. The block
/// itself is both the plaintext and part of the feedforward step.
#[inline(always)]
pub fn ubi(state: &mut Chaining, plaintext: &BlockWords, tweak: UbiTweak) {
  let mut encrypted = *plaintext;
  encrypt(&mut encrypted, state, &tweak.as_words());

  // UBI uses MMO feedforward: encrypt the block, then xor the plaintext
  // back in to form the next chaining value.
  let mut index = 0;
  while index < NW {
    state[index] = encrypted[index] ^ plaintext[index];
    index += 1;
  }
}

/// Hashes the message stream as one UBI message stream.
fn hash_message_blocks(state: &mut Chaining, data: &[u8]) {
  let mut pos = 0usize;
  let mut blocks = 0u64;

  // UBI counts bytes, not blocks. The tweak position is the total number
  // of message bytes seen after each block.
  while pos + BLOCK < data.len() {
    let tweak = UbiTweak {
      position: (blocks + 1) << 6,
      kind: TYPE_MSG,
      first: blocks == 0,
      final_block: false,
    };
    ubi(state, &load_block(&data[pos..pos + BLOCK]), tweak);
    pos += BLOCK;
    blocks += 1;
  }

  let remaining = data.len() - pos;
  let mut last = [0u8; BLOCK];
  last[..remaining].copy_from_slice(&data[pos..]);
  let tweak = UbiTweak {
    position: (blocks << 6).wrapping_add(remaining as u64),
    kind: TYPE_MSG,
    first: blocks == 0,
    final_block: true,
  };
  ubi(state, &load_block(&last), tweak);
}

/// Runs the UBI output step and leaves the digest in `state`.
///
/// Skein treats output generation as a separate UBI stream with its own
/// block type. Skein-512 needs only the first 64 output bytes.
#[inline(always)]
pub fn output_block(state: &mut Chaining) {
  let zero = [0u64; NW];
  let tweak = UbiTweak {
    position: 8,
    kind: TYPE_OUTPUT,
    first: true,
    final_block: true,
  };
  ubi(state, &zero, tweak);
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let mut state = IV;
  hash_message_blocks(&mut state, data);
  output_block(&mut state);

  let mut out = [0u8; 64];
  let mut index = 0;
  while index < NW {
    store_u64_le(&mut out, index, state[index]);
    index += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("skein", hash512);
  }
}
