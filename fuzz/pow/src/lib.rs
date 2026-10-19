//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential checks of `dash-pow` against the sphlib reference.

use digest::FixedOutputReset;

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
/// Header flag for a reset pass before the scheduled run.
const FLAG_RESET: u8 = 0x10;
/// Header flag for a clone halfway through the schedule.
const FLAG_CLONE: u8 = 0x20;

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

/// How a hasher is driven over one message.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Plan {
  /// Bytes past 16-byte alignment that the message starts at.
  pub offset: usize,
  /// Whether the hasher first hashes the message and resets.
  pub reset: bool,
  /// Whether a clone of the hasher halfway through is finished too.
  pub clone: bool,
  /// Message positions where one update ends and the next begins.
  pub cuts: Vec<usize>,
}

impl Plan {
  /// Splits a fuzz input into the plan it encodes and the message.
  ///
  /// Byte 0 holds the misalignment in its low four bits, the reset pass in
  /// bit 4 and the clone in bit 5. Byte 1 counts the update lengths that
  /// follow, and the rest of the input is the message.
  pub fn decode(input: &[u8]) -> (Self, &[u8]) {
    let (&flags, rest) = input.split_first().unwrap_or((&0, &[]));
    let (&count, rest) = rest.split_first().unwrap_or((&0, &[]));
    let (lengths, message) = rest.split_at(usize::from(count).min(rest.len()));
    let mut at = 0;
    let cuts = lengths
      .iter()
      .map(|&length| {
        at = (at + usize::from(length)).min(message.len());
        at
      })
      .collect();
    let plan = Self {
      offset: usize::from(flags) % OFFSETS,
      reset: flags & FLAG_RESET != 0,
      clone: flags & FLAG_CLONE != 0,
      cuts,
    };
    (plan, message)
  }
}

/// Asserts `D` agrees with `theirs` on `message` driven by `plan`. X11 feeds
/// its stages 64 and 80 bytes, so those prefixes are checked too.
pub fn assert_plan<D, T>(name: &str, theirs: fn(&[u8]) -> T, message: &[u8], plan: &Plan)
where
  D: digest::Digest + FixedOutputReset + Clone,
  T: AsRef<[u8]>,
{
  let offset = plan.offset;
  let (buffer, start) = misalign(message, offset);
  let shifted = &buffer[start..start + message.len()];
  let prefixes = [message.len(), 64, 80];
  for len in prefixes.into_iter().filter(|&len| len <= message.len()) {
    let input = &shifted[..len];
    let expected = theirs(input);
    let mut hasher = D::new();
    if plan.reset {
      digest::Digest::update(&mut hasher, input);
      let got = hasher.finalize_reset();
      assert_eq!(
        &got[..],
        expected.as_ref(),
        "{name} differs on {len} bytes before a reset"
      );
    }
    let cuts: Vec<usize> = plan.cuts.iter().copied().filter(|&cut| cut <= len).collect();
    // The clone forks after half of the updates, rounded down.
    let fork = (cuts.len() + 1) / 2;
    let mut from = 0;
    for (index, &to) in cuts.iter().chain(&[len]).enumerate() {
      if plan.clone && index == fork {
        let got = hasher.clone().finalize();
        assert_eq!(
          &got[..],
          theirs(&input[..from]).as_ref(),
          "{name} differs on a clone after {from} of {len} bytes at offset {offset}"
        );
      }
      digest::Digest::update(&mut hasher, &input[from..to]);
      from = to;
    }
    let got = hasher.finalize();
    assert_eq!(
      &got[..],
      expected.as_ref(),
      "{name} differs on {len} bytes at offset {offset} cut at {cuts:?}"
    );
  }
}

/// Decodes the fuzz `input` and runs [`assert_plan`] on its message.
pub fn assert_input<D, T>(name: &str, theirs: fn(&[u8]) -> T, input: &[u8])
where
  D: digest::Digest + FixedOutputReset + Clone,
  T: AsRef<[u8]>,
{
  let (plan, message) = Plan::decode(input);
  assert_plan::<D, T>(name, theirs, message, &plan);
}

/// The X11 chain over sphlib, truncated to 256 bits.
pub fn x11(data: &[u8]) -> [u8; 32] {
  const CHAIN: [fn(&[u8]) -> [u8; 64]; 10] = [
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

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic, reason = "test code")]
mod tests {
  use super::*;

  use dash_pow::__private::{
    Blake512, Bmw512, CubeHash512, Echo512, Groestl512, Jh512, Keccak512, Luffa512, Shavite512, Simd512, Skein512,
  };
  use dash_pow::X11;
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

    /// Asserts the stage agrees with sphlib on `message` driven by `plan`.
    fn assert_plan(self, message: &[u8], plan: &Plan) {
      let name = self.name();
      match self {
        Self::Blake => assert_plan::<Blake512, _>(name, sph::blake, message, plan),
        Self::Bmw => assert_plan::<Bmw512, _>(name, sph::bmw, message, plan),
        Self::CubeHash => assert_plan::<CubeHash512, _>(name, sph::cubehash, message, plan),
        Self::Echo => assert_plan::<Echo512, _>(name, sph::echo, message, plan),
        Self::Groestl => assert_plan::<Groestl512, _>(name, sph::groestl, message, plan),
        Self::Jh => assert_plan::<Jh512, _>(name, sph::jh, message, plan),
        Self::Keccak => assert_plan::<Keccak512, _>(name, sph::keccak, message, plan),
        Self::Luffa => assert_plan::<Luffa512, _>(name, sph::luffa, message, plan),
        Self::Shavite => assert_plan::<Shavite512, _>(name, sph::shavite, message, plan),
        Self::Simd => assert_plan::<Simd512, _>(name, sph::simd, message, plan),
        Self::Skein => assert_plan::<Skein512, _>(name, sph::skein, message, plan),
        Self::X11 => assert_plan::<X11, _>(name, x11, message, plan),
      }
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

  /// The header splits off the plan, and update lengths accumulate into cuts
  /// that stop at the end of the message.
  #[rstest]
  #[case::empty(&[], Plan::default(), &[])]
  #[case::flags_only(&[0x3f], Plan { offset: 15, reset: true, clone: true, cuts: vec![] }, &[])]
  #[case::lengths(&[0x01, 2, 3, 0, 9, 9, 9, 9], Plan { offset: 1, cuts: vec![3, 3], ..Plan::default() }, &[9, 9, 9, 9])]
  #[case::clamped(&[0x00, 2, 9, 9, 7, 7], Plan { cuts: vec![2, 2], ..Plan::default() }, &[7, 7])]
  #[case::count_past_end(&[0x00, 9, 1], Plan { cuts: vec![0], ..Plan::default() }, &[])]
  fn plan_decodes(#[case] input: &[u8], #[case] plan: Plan, #[case] message: &[u8]) {
    assert_eq!(Plan::decode(input), (plan, message));
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
    // Pieces of a prime length keep the cuts moving across block boundaries.
    const PIECE: usize = 1_000_003;
    let data = input(CARRY + 129);
    // CARRY - 1 crosses the carry inside the final block's counter keys.
    // CARRY puts the carry on a block boundary. CARRY + 129 adds a partial
    // block after the carry.
    for len in [CARRY - 1, CARRY, CARRY + 129] {
      let pieces = Plan {
        cuts: (1..len / PIECE).map(|piece| piece * PIECE).collect(),
        ..Plan::default()
      };
      stage.assert_plan(&data[..len], &Plan::default());
      stage.assert_plan(&data[..len], &pieces);
    }
  }

  /// Every stage and the chain agree with sphlib on 0 to 512 bytes at every
  /// misalignment, without a fuzzing engine. Each length and offset takes
  /// one schedule in turn, with the reset and clone passes on alternately.
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
      // Cuts at and beside each block boundary leave the buffer empty, one
      // byte in or one byte short of full.
      let mut schedules: Vec<Vec<usize>> = vec![Vec::new(), (1..len).collect()];
      for block in [32, 64, 72, 128] {
        for shift in [0, 1, block - 1] {
          schedules.push((1..len).filter(|cut| cut % block == shift).collect());
        }
      }
      for offset in 0..OFFSETS {
        let plan = Plan {
          offset,
          reset: offset & 1 != 0,
          clone: offset & 2 != 0,
          cuts: schedules[(len + offset) % schedules.len()].clone(),
        };
        stage.assert_plan(&data, &plan);
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
    for input in corpus(stage.name()) {
      let (plan, message) = Plan::decode(&input);
      stage.assert_plan(message, &plan);
    }
  }
}
