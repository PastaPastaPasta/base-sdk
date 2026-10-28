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
  ($algo:ident, $hasher:ident, $x11_len:literal) => {
    mod $algo {
      use super::*;

      #[divan::bench(args = [32, 64, 80, 128, 512, 1024, 2048])]
      fn digest(bencher: Bencher, n: usize) {
        let input = vec![0u8; n];
        bencher
          .counter(1u32)
          .bench(|| black_box(pow_crate::$hasher::digest(black_box(&input))));
      }

      #[divan::bench]
      fn x11(bencher: Bencher) {
        let input = [0u8; $x11_len];
        bencher.counter(1u32).bench(|| {
          // Hides the bytes but not the length, as the chain passes it.
          let input: &[u8; $x11_len] = black_box(&input);
          black_box(pow_crate::$hasher::digest(input))
        });
      }
    }
  };
}

mod pow {
  use super::*;

  #[divan::bench(args = [32, 64, 80, 128, 512, 1024, 2048])]
  fn digest(bencher: Bencher, n: usize) {
    let input = vec![0u8; n];
    bencher
      .counter(1u32)
      .bench(|| black_box(X11::digest(black_box(&input))));
  }

  /// The 80-byte block header fed in two pieces.
  #[divan::bench]
  fn update(bencher: Bencher) {
    let input = [0u8; 80];
    bencher.counter(1u32).bench(|| {
      let mut hasher = X11::new();
      Digest::update(&mut hasher, black_box(&input[..36]));
      Digest::update(&mut hasher, black_box(&input[36..]));
      black_box(hasher.finalize())
    });
  }
}

bench_algo!(blake, Blake512, 80);
bench_algo!(bmw, Bmw512, 64);
bench_algo!(cubehash, CubeHash512, 64);
bench_algo!(echo, Echo512, 64);
bench_algo!(groestl, Groestl512, 64);
bench_algo!(jh, Jh512, 64);
bench_algo!(keccak, Keccak512, 64);
bench_algo!(luffa, Luffa512, 64);
bench_algo!(shavite, Shavite512, 64);
bench_algo!(simd, Simd512, 64);
bench_algo!(skein, Skein512, 64);

fn main() {
  divan::main();
}
