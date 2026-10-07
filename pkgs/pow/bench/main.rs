//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of work total and constituent benchmarks.

use dash_pow::{__private as pow_crate, hash as pow_hash};
use divan::{black_box, Bencher};

macro_rules! bench_algo {
  (@hash512 $name:ident, $path:path) => {
    use super::*;
    #[divan::bench(args = [32, 80, 128, 512, 1024, 2048])]
    fn $name(bencher: Bencher, n: usize) {
      let input = vec![0u8; n];
      bencher
        .counter(1u32)
        .bench(|| black_box($path(black_box(&input))));
    }
  };
  ($algo:ident) => {
    mod $algo {
      bench_algo!(@hash512 hash512, pow_crate::$algo::hash512);
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

bench_algo!(blake);
bench_algo!(bmw);
bench_algo!(cubehash);
bench_algo!(echo);
bench_algo!(groestl);
bench_algo!(jh);
bench_algo!(keccak);
bench_algo!(luffa);
bench_algo!(shavite);
bench_algo!(simd);
bench_algo!(skein);

fn main() {
  divan::main();
}
