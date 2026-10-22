//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! Skein-512 hash function.

use crate::consts::skein::{BLOCK, IV, NW};
use crate::util::buffer::{Buffer, Compress};
use crate::util::impl_digest;
use crate::util::memops::{digest_from_u64_le, load_u64s_le};
use crate::util::threefish::encrypt;

use digest::{FixedOutput, Output, Update};

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

/// Applies one UBI step.
///
/// UBI uses Threefish with the current chaining value as the key. The block
/// itself is both the plaintext and part of the feedforward step.
#[inline(always)]
fn ubi(state: &mut Chaining, plaintext: &BlockWords, tweak: UbiTweak) {
  let mut encrypted = *plaintext;
  encrypt(&mut encrypted, state, &tweak.as_words());

  // The MMO feedforward xors the plaintext back into the encrypted block
  // to form the next chaining value.
  let mut index = 0;
  while index < NW {
    state[index] = encrypted[index] ^ plaintext[index];
    index += 1;
  }
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

/// Chaining value and byte count.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  h: Chaining,
  /// Bytes compressed so far.
  position: u64,
}

impl Core {
  /// Applies one message block, counting its `bytes`.
  #[inline(always)]
  fn ubi(&mut self, block: &[u8; BLOCK], bytes: u64, final_block: bool) {
    let tweak = UbiTweak {
      position: self.position.wrapping_add(bytes),
      kind: TYPE_MSG,
      first: self.position == 0,
      final_block,
    };
    self.position = tweak.position;
    ubi(&mut self.h, &load_u64s_le(block), tweak);
  }
}

impl Compress<BLOCK> for Core {
  #[inline(always)]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    self.ubi(block, BLOCK as u64, false);
  }
}

/// Streaming Skein-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Skein512 {
  core: Core,
  /// The last block is flagged rather than followed by padding, so a full
  /// block waits in the buffer until a byte follows it.
  buffer: Buffer<BLOCK>,
}

impl Default for Skein512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core { h: IV, position: 0 },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Skein512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update_lagging(data, &mut self.core);
  }
}

impl FixedOutput for Skein512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    // UBI counts bytes, so the tweak position of the last block is the
    // message length whatever its zero padding.
    let remaining = self.buffer.len() as u64;
    self.core.ubi(self.buffer.zero_padded(), remaining, true);
    output_block(&mut self.core.h);
    out.copy_from_slice(&digest_from_u64_le(&self.core.h));
  }
}

impl_digest!(Skein512, U64);

#[cfg(test)]
mod tests {
  use super::Skein512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Skein512>("skein");
  }
}
