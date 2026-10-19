//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential checks of `dash-pow` against the sphlib reference.

use digest::consts::U64;
use digest::OutputSizeUser;

/// A 512-bit digest function.
pub type Digest = fn(&[u8]) -> [u8; 64];

/// Hashes `data` with the `dash-pow` stage `D` in one update.
pub fn digest512<D: digest::Digest + OutputSizeUser<OutputSize = U64>>(data: &[u8]) -> [u8; 64] {
  D::digest(data).into()
}

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
  bmw => dash_sph_bmw,
  cubehash => dash_sph_cubehash,
  echo => dash_sph_echo,
  groestl => dash_sph_groestl,
  jh => dash_sph_jh,
  keccak => dash_sph_keccak,
  luffa => dash_sph_luffa,
  shavite => dash_sph_shavite,
  simd => dash_sph_simd,
  skein => dash_sph_skein,
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

/// The X11 chain over sphlib, truncated to 256 bits.
pub fn x11(data: &[u8]) -> [u8; 32] {
  const CHAIN: [Digest; 10] = [
    sph::bmw,
    sph::groestl,
    sph::skein,
    sph::jh,
    sph::keccak,
    sph::luffa,
    sph::cubehash,
    sph::shavite,
    sph::simd,
    sph::echo,
  ];
  let digest = CHAIN.iter().fold(sph::blake(data), |digest, stage| stage(&digest));
  let mut out = [0u8; 32];
  out.copy_from_slice(&digest[..32]);
  out
}

/// Asserts the X11 chain agrees with sphlib on `data` placed at `offset`.
pub fn assert_same_x11_at(data: &[u8], offset: usize) {
  let (buffer, start) = misalign(data, offset);
  let shifted = &buffer[start..start + data.len()];
  assert_eq!(
    dash_pow::hash(shifted),
    x11(shifted),
    "x11 differs on {} bytes at offset {offset}",
    data.len(),
  );
}

/// Runs [`assert_same_x11_at`] at the misalignment `data` selects.
pub fn assert_same_x11(data: &[u8]) {
  assert_same_x11_at(data, offset_for(data));
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic, reason = "test code")]
mod tests {
  use super::*;

  use dash_pow::__private::{
    cubehash, echo, shavite, simd, Blake512, Bmw512, Groestl512, Jh512, Keccak512, Luffa512, Skein512,
  };
  use rstest::rstest;

  use std::fs;
  use std::ops::Deref;
  use std::path::{Path, PathBuf};

  /// An X11 stage, or the whole chain, checked against sphlib.
  #[derive(Clone, Copy, Debug)]
  enum Stage {
    Blake,
    Bmw,
    CubeHash,
    Echo,
    Groestl,
    Jh,
    Keccak,
    Luffa,
    Shavite,
    Simd,
    Skein,
    X11,
  }

  impl Stage {
    /// Name of the corpus directory, also used in failure messages.
    fn name(self) -> &'static str {
      match self {
        Self::Blake => "blake",
        Self::Bmw => "bmw",
        Self::CubeHash => "cubehash",
        Self::Echo => "echo",
        Self::Groestl => "groestl",
        Self::Jh => "jh",
        Self::Keccak => "keccak",
        Self::Luffa => "luffa",
        Self::Shavite => "shavite",
        Self::Simd => "simd",
        Self::Skein => "skein",
        Self::X11 => "x11",
      }
    }

    /// Asserts the stage agrees with sphlib on `data` placed at `offset`.
    fn assert_same_at(self, data: &[u8], offset: usize) {
      let (ours, theirs): (Digest, Digest) = match self {
        Self::Blake => (digest512::<Blake512>, sph::blake),
        Self::Bmw => (digest512::<Bmw512>, sph::bmw),
        Self::CubeHash => (cubehash::hash512, sph::cubehash),
        Self::Echo => (echo::hash512, sph::echo),
        Self::Groestl => (digest512::<Groestl512>, sph::groestl),
        Self::Jh => (digest512::<Jh512>, sph::jh),
        Self::Keccak => (digest512::<Keccak512>, sph::keccak),
        Self::Luffa => (digest512::<Luffa512>, sph::luffa),
        Self::Shavite => (shavite::hash512, sph::shavite),
        Self::Simd => (simd::hash512, sph::simd),
        Self::Skein => (digest512::<Skein512>, sph::skein),
        Self::X11 => return assert_same_x11_at(data, offset),
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

  /// Echo and SHAvite agree with sphlib across their 32-bit bit-count carry.
  /// Fuzzer inputs never reach the 2^29 bytes the carry needs.
  #[rstest]
  #[ignore = "hashes 512 MiB inputs, run with `--release --ignored`"]
  fn counter_word_carries(#[values(Stage::Echo, Stage::Shavite)] stage: Stage) {
    const CARRY: usize = 1 << 29;
    let data = input(CARRY + 129);
    // CARRY - 1 crosses the carry inside the final block's counter keys.
    // CARRY puts the carry on a block boundary. CARRY + 129 adds a partial
    // block after the carry.
    for len in [CARRY - 1, CARRY, CARRY + 129] {
      stage.assert_same_at(&data[..len], 0);
    }
  }

  /// Every stage and the chain agree with sphlib on 0 to 512 bytes at every
  /// misalignment, without a fuzzing engine.
  #[rstest]
  fn sweep(
    #[values(
      Stage::Blake,
      Stage::Bmw,
      Stage::CubeHash,
      Stage::Echo,
      Stage::Groestl,
      Stage::Jh,
      Stage::Keccak,
      Stage::Luffa,
      Stage::Shavite,
      Stage::Simd,
      Stage::Skein,
      Stage::X11
    )]
    stage: Stage,
  ) {
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
  fn corpora(
    #[values(
      Stage::Blake,
      Stage::Bmw,
      Stage::CubeHash,
      Stage::Echo,
      Stage::Groestl,
      Stage::Jh,
      Stage::Keccak,
      Stage::Luffa,
      Stage::Shavite,
      Stage::Simd,
      Stage::Skein,
      Stage::X11
    )]
    stage: Stage,
  ) {
    for data in corpus(stage.name()) {
      stage.assert_same_at(&data, offset_for(&data));
    }
  }
}
