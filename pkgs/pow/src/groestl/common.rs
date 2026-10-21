//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! Streaming Groestl-512 over the selected backend.

use super::backend;
use crate::consts::groestl::{BLOCK, IV_ROWS};
use crate::util::buffer::{Buffer, Compress};
use crate::util::{impl_digest, impl_hash};

use digest::{FixedOutput, Output, Update};

/// Chaining value and block count.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Core {
  h: [backend::Row; 8],
  blocks: u64,
}

impl Compress<BLOCK> for Core {
  #[inline(always)]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    backend::compress_block(&mut self.h, block);
    self.blocks = self.blocks.wrapping_add(1);
  }
}

impl_hash!(Core, [h], [blocks]);

/// Streaming Groestl-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Groestl512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Groestl512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core {
        h: IV_ROWS.map(backend::Row::new),
        blocks: 0,
      },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Groestl512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Groestl512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    let remaining = self.buffer.len();
    // The last eight bytes hold the total block count, padding included, so
    // a tail reaching byte 120 spills into a second block.
    let block = self.buffer.pad(0x80);
    if remaining < 120 {
      block[120..].copy_from_slice(&self.core.blocks.wrapping_add(1).to_be_bytes());
      self.core.compress(block);
    } else {
      self.core.compress(block);
      let mut last = [0u8; BLOCK];
      last[120..].copy_from_slice(&self.core.blocks.wrapping_add(1).to_be_bytes());
      self.core.compress(&last);
    }
    backend::output_transform(&mut self.core.h);

    let mut digest = [0u8; 64];
    backend::extract_right_half(&self.core.h, &mut digest);
    out.copy_from_slice(&digest);
  }
}

impl_digest!(Groestl512, U64);

#[cfg(test)]
mod tests {
  use super::Groestl512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Groestl512>("groestl");
  }
}
