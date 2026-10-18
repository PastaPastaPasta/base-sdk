//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential checks of `dash-pow` against the sphlib reference.

/// A 512-bit digest function.
pub type Digest = fn(&[u8]) -> [u8; 64];

macro_rules! reference {
  ($($stage:ident => $symbol:ident),* $(,)?) => {
    /// The sphlib digests, one per stage.
    #[expect(unsafe_code, reason = "sphlib FFI")]
    pub mod sph {
      extern "C" {
        $(fn $symbol(data: *const u8, len: usize, out: *mut u8);)*
      }

      $(
        pub fn $stage(data: &[u8]) -> [u8; 64] {
          let mut out = [0u8; 64];
          // SAFETY: sphlib reads `len` bytes of `data` and writes 64 to `out`.
          unsafe { $symbol(data.as_ptr(), data.len(), out.as_mut_ptr()) };
          out
        }
      )*
    }
  };
}

reference!(
  blake => dash_sph_blake,
);

/// Misalignments tried, every offset within a 16-byte vector.
pub const OFFSETS: usize = 16;

/// Copies `data` to an address `offset` bytes past 16-byte alignment.
///
/// Returns the buffer and where the copy starts within it.
fn misalign(data: &[u8], offset: usize) -> (Vec<u8>, usize) {
  let mut buffer = vec![0u8; data.len() + 2 * OFFSETS];
  let base = buffer.as_ptr() as usize;
  let start = (OFFSETS - base % OFFSETS + offset) % OFFSETS;
  buffer[start..start + data.len()].copy_from_slice(data);
  (buffer, start)
}

/// Picks the misalignment for `data` from its first byte, so the fuzzer
/// steers it without the input changing meaning.
fn offset_for(data: &[u8]) -> usize {
  data.first().map_or(0, |&byte| usize::from(byte) % OFFSETS)
}

/// Asserts `ours` and `theirs` agree on `data` placed at `offset`.
/// X11 feeds its stages 64 and 80 bytes, so those prefixes are checked too.
pub fn assert_same_at(name: &str, ours: Digest, theirs: Digest, data: &[u8], offset: usize) {
  let (buffer, start) = misalign(data, offset);
  let shifted = &buffer[start..start + data.len()];
  let prefixes = [data.len(), 64, 80];
  for len in prefixes.into_iter().filter(|&len| len <= data.len()) {
    let input = &shifted[..len];
    assert_eq!(
      ours(input),
      theirs(input),
      "{name} differs on {len} bytes at offset {offset}"
    );
  }
}

/// Runs [`assert_same_at`] at the misalignment `data` selects.
pub fn assert_same(name: &str, ours: Digest, theirs: Digest, data: &[u8]) {
  assert_same_at(name, ours, theirs, data, offset_for(data));
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic, reason = "test code")]
mod tests {
  use super::*;

  use dash_pow::__private::blake;
  use rstest::rstest;

  use std::fs;
  use std::ops::Deref;
  use std::path::{Path, PathBuf};

  /// An X11 stage, checked against sphlib.
  #[derive(Clone, Copy, Debug)]
  enum Stage {
    Blake,
  }

  impl Stage {
    /// Name of the corpus directory, also used in failure messages.
    fn name(self) -> &'static str {
      match self {
        Self::Blake => "blake",
      }
    }

    /// Asserts the stage agrees with sphlib on `data` placed at `offset`.
    fn assert_same_at(self, data: &[u8], offset: usize) {
      let (ours, theirs): (Digest, Digest) = match self {
        Self::Blake => (blake::hash512, sph::blake),
      };
      assert_same_at(self.name(), ours, theirs, data, offset);
    }
  }

  /// One corpus input, which names its file if a check panics on it.
  struct Input {
    path: PathBuf,
    data: Vec<u8>,
  }

  impl Deref for Input {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
      &self.data
    }
  }

  impl Drop for Input {
    fn drop(&mut self) {
      if std::thread::panicking() {
        eprintln!("failing input {}", self.path.display());
      }
    }
  }

  /// Reads every input of the corpus named `name`, in file name order.
  /// Each file is read as it is reached, so a panic names one input only.
  fn corpus(name: &str) -> impl Iterator<Item = Input> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpora").join(name);
    let mut paths: Vec<_> = fs::read_dir(&dir)
      .unwrap_or_else(|err| panic!("reading {}: {err}", dir.display()))
      .map(|entry| entry.expect("corpus entry").path())
      .collect();
    paths.sort();
    assert!(!paths.is_empty(), "{} holds no inputs", dir.display());
    paths.into_iter().map(|path| Input {
      data: fs::read(&path).expect("corpus input"),
      path,
    })
  }

  /// The copy lands exactly `offset` bytes past 16-byte alignment.
  #[test]
  fn misalign_places_copy() {
    let data = [1u8, 2, 3, 4, 5];
    for offset in 0..OFFSETS {
      let (buffer, start) = misalign(&data, offset);
      assert_eq!((buffer.as_ptr() as usize + start) % OFFSETS, offset);
      assert_eq!(&buffer[start..start + data.len()], &data);
    }
  }

  /// Fills `len` bytes from a fixed xorshift stream.
  fn input(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ len as u64;
    (0..len)
      .map(|_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
      })
      .collect()
  }

  /// Every stage agrees with sphlib across four blocks of lengths at
  /// every misalignment, without a fuzzing engine.
  #[rstest]
  fn sweep(#[values(Stage::Blake)] stage: Stage) {
    for len in 0..=512 {
      let data = input(len);
      for offset in 0..OFFSETS {
        stage.assert_same_at(&data, offset);
      }
    }
  }

  /// Every input of every corpus still agrees with sphlib, so a plain
  /// `cargo test` replays what the fuzzers found without running one.
  #[rstest]
  fn corpora(#[values(Stage::Blake)] stage: Stage) {
    for data in corpus(stage.name()) {
      stage.assert_same_at(&data, offset_for(&data));
    }
  }
}
