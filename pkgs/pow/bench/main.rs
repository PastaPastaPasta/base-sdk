//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of work total and constituent benchmarks.

use dash_pow::{__private as pow_crate, X11};
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
    bencher
      .counter(1u32)
      .bench(|| black_box(X11::digest(black_box(&input))));
  }
}

bench_algo!(blake => pow_crate::Blake512::digest);
bench_algo!(bmw => pow_crate::Bmw512::digest);
bench_algo!(cubehash => pow_crate::CubeHash512::digest);
bench_algo!(echo => pow_crate::Echo512::digest);
bench_algo!(groestl => pow_crate::Groestl512::digest);
bench_algo!(jh => pow_crate::Jh512::digest);
bench_algo!(keccak => pow_crate::Keccak512::digest);
bench_algo!(luffa => pow_crate::Luffa512::digest);
bench_algo!(shavite => pow_crate::Shavite512::digest);
bench_algo!(simd => pow_crate::Simd512::digest);
bench_algo!(skein => pow_crate::Skein512::digest);

fn main() {
  divan::main();
}
