//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof-of-work hash used by Dash.
//!
//! Chains eleven 512-bit hash algorithms (Blake, BMW, Groestl, Skein, JH,
//! Keccak, Luffa, CubeHash, SHAvite, SIMD, Echo) and truncates the final output
//! to 256 bits.

#![no_std]
#![cfg_attr(feature = "simd", feature(portable_simd))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(all(
  not(any(doc, feature = "portable")),
  target_arch = "x86_64",
  not(all(
    target_feature = "aes",
    target_feature = "avx",
    target_feature = "avx2",
    target_feature = "bmi1",
    target_feature = "bmi2",
    target_feature = "f16c",
    target_feature = "fma",
    target_feature = "lzcnt",
    target_feature = "movbe",
    target_feature = "xsave",
  ))
))]
compile_error!(concat!(
  "dash-pow requires x86-64-v3 and AES, build with ",
  "`-C target-cpu=x86-64-v3 -C target-feature=+aes` or enable `portable`",
));
#[cfg(all(
  not(any(doc, feature = "portable")),
  target_arch = "aarch64",
  not(all(target_feature = "neon", target_feature = "aes"))
))]
compile_error!("dash-pow requires NEON and AES, build with `-C target-feature=+neon,+aes` or enable `portable`");
#[cfg(all(
  not(any(doc, feature = "portable")),
  target_arch = "wasm32",
  not(target_feature = "simd128")
))]
compile_error!("dash-pow requires 128-bit SIMD, build with `-C target-feature=+simd128` or enable `portable`");

#[cfg_attr(
  not(any(test, feature = "simd")),
  expect(dead_code, reason = "only the SIMD backends use the block interface")
)]
mod aes;
mod blake;
mod bmw;
mod cubehash;
mod echo;
mod groestl;
mod jh;
mod keccak;
mod luffa;
mod shavite;
mod simd_hash;
mod skein;
mod util;

#[doc(hidden)]
pub mod __private {
  pub mod blake {
    pub use crate::blake::*;
  }
  pub mod bmw {
    pub use crate::bmw::*;
  }
  pub mod cubehash {
    pub use crate::cubehash::*;
  }
  pub mod echo {
    pub use crate::echo::*;
  }
  pub mod groestl {
    pub use crate::groestl::*;
  }
  pub mod jh {
    pub use crate::jh::*;
  }
  pub mod keccak {
    pub use crate::keccak::*;
  }
  pub mod luffa {
    pub use crate::luffa::*;
  }
  pub mod shavite {
    pub use crate::shavite::*;
  }
  pub mod simd_hash {
    pub use crate::simd_hash::*;
  }
  pub mod skein {
    pub use crate::skein::*;
  }
}

/// Computes the Dash proof-of-work hash.
///
/// The digest is little-endian, matching the consensus byte order of a
/// block hash.
pub fn hash(data: &[u8]) -> [u8; 32] {
  let h = blake::hash512(data);
  let h = bmw::hash512(&h);
  let h = groestl::hash512(&h);
  let h = skein::hash512(&h);
  let h = jh::hash512(&h);
  let h = keccak::hash512(&h);
  let h = luffa::hash512(&h);
  let h = cubehash::hash512(&h);
  let h = shavite::hash512(&h);
  let h = simd_hash::hash512(&h);
  let h = echo::hash512(&h);
  let mut out = [0u8; 32];
  out.copy_from_slice(&h[..32]);
  out
}
