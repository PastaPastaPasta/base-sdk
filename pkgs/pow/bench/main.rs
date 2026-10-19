//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of work total and constituent benchmarks.

use dash_pow::{__private as pow_crate, hash as pow_hash};
use digest::Digest;
use divan::{black_box, Bencher};

macro_rules! bench_algo {
  (@hash512 $name:ident, $hash:expr) => {
    use super::*;
    #[divan::bench(args = [32, 80, 128, 512, 1024, 2048])]
    fn $name(bencher: Bencher, n: usize) {
      let input = vec![0u8; n];
      bencher
        .counter(1u32)
        .bench(|| black_box($hash(black_box(&input))));
    }
  };
  ($algo:ident => $hash:expr) => {
    mod $algo {
      bench_algo!(@hash512 hash512, $hash);
    }
  };
}

mod pow {
  use super::*;

  #[divan::bench(args = [32, 80, 128, 512, 1024, 2048])]
  fn hash(bencher: Bencher, n: usize) {
    let input = vec![0u8; n];
    bencher.counter(1u32).bench(|| black_box(pow_hash(black_box(&input))));
  }
}

bench_algo!(blake => pow_crate::Blake512::digest);
bench_algo!(bmw => pow_crate::Bmw512::digest);
bench_algo!(cubehash => pow_crate::cubehash::hash512);
bench_algo!(echo => pow_crate::echo::hash512);
bench_algo!(groestl => pow_crate::groestl::hash512);
bench_algo!(jh => pow_crate::jh::hash512);
bench_algo!(keccak => pow_crate::keccak::hash512);
bench_algo!(luffa => pow_crate::luffa::hash512);
bench_algo!(shavite => pow_crate::shavite::hash512);
bench_algo!(simd => pow_crate::simd::hash512);
bench_algo!(skein => pow_crate::skein::hash512);

fn main() {
  divan::main();
}
