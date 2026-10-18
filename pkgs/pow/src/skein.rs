//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Skein-512 hash function.

use crate::consts::skein::{BLOCK, IV, NW};
use crate::util::memops::{digest_from_u64_le, load_u64_le, zero_extend};
use crate::util::threefish::encrypt;

/// UBI type code for message blocks.
const TYPE_MSG: u64 = 48;
/// UBI type code for output blocks.
const TYPE_OUTPUT: u64 = 63;
/// Marks the first block in one UBI stream.
const FLAG_FIRST: u64 = 1 << 62;
/// Marks the final block in one UBI stream.
const FLAG_FINAL: u64 = 1 << 63;

/// Skein chaining value, stored as eight 64-bit words.
type Chaining = [u64; NW];
/// One 64-byte Skein block decoded as eight little-endian words.
type BlockWords = [u64; NW];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UbiTweak {
  /// Total number of bytes seen so far in this UBI stream.
  position: u64,
  /// UBI block type, such as "message" or "output".
  kind: u64,
  /// Marks the first block in a UBI stream.
  first: bool,
  /// Marks the final block in a UBI stream.
  final_block: bool,
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
fn ubi(state: &mut Chaining, plaintext: &BlockWords, tweak: UbiTweak) {
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
  let mut blocks = 0u64;

  // The last block carries the final flag even when it is full, so it is
  // split off before the loop. An empty message still has one final block.
  let (body, tail) = data.split_at(data.len().saturating_sub(1) / BLOCK * BLOCK);

  // UBI counts bytes, not blocks. The tweak position is the total number
  // of message bytes seen after each block.
  for block in body.as_chunks::<BLOCK>().0 {
    let tweak = UbiTweak {
      position: (blocks + 1) << 6,
      kind: TYPE_MSG,
      first: blocks == 0,
      final_block: false,
    };
    ubi(state, &load_block(block), tweak);
    blocks += 1;
  }

  let remaining = tail.len();
  let last: [u8; BLOCK] = zero_extend(tail);
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
fn output_block(state: &mut Chaining) {
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
  digest_from_u64_le(&state)
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
