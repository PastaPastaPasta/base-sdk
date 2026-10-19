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
#![deny(
  unsafe_op_in_unsafe_fn,
  clippy::undocumented_unsafe_blocks,
  clippy::unnecessary_safety_comment
)]

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

mod aes;
mod blake;
mod bmw;
mod consts;
mod cubehash;
mod echo;
mod groestl;
mod jh;
mod keccak;
mod luffa;
mod shavite;
mod simd;
mod skein;
#[cfg(test)]
mod tests;
mod util;

#[doc(hidden)]
pub mod __private {
  pub use crate::blake::Blake512;
  pub use crate::bmw::Bmw512;
  pub use crate::groestl::Groestl512;
  pub use crate::jh::Jh512;
  pub use crate::keccak::Keccak512;
  pub use crate::luffa::Luffa512;
  pub use crate::skein::Skein512;

  pub mod cubehash {
    pub use crate::cubehash::hash512;
  }
  pub mod echo {
    pub use crate::echo::hash512;
  }
  pub mod shavite {
    pub use crate::shavite::hash512;
  }
  pub mod simd {
    pub use crate::simd::hash512;
  }
}

use blake::Blake512;
use bmw::Bmw512;
use digest::Digest;
use groestl::Groestl512;
use jh::Jh512;
use keccak::Keccak512;
use luffa::Luffa512;
use skein::Skein512;

/// Computes the Dash proof-of-work hash.
///
/// The digest is little-endian, matching the consensus byte order of a
/// block hash.
pub fn hash(data: &[u8]) -> [u8; 32] {
  let h = Blake512::digest(data);
  let h = Bmw512::digest(h);
  let h = Groestl512::digest(h);
  let h = Skein512::digest(h);
  let h = Jh512::digest(h);
  let h = Keccak512::digest(h);
  let h = Luffa512::digest(h);
  let h = cubehash::hash512(&h);
  let h = shavite::hash512(&h);
  let h = simd::hash512(&h);
  let h = echo::hash512(&h);
  let mut out = [0u8; 32];
  out.copy_from_slice(&h[..32]);
  out
}
