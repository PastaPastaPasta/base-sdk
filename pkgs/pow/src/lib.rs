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
  pub mod blake {
    pub use crate::blake::hash512;
  }
  pub mod bmw {
    pub use crate::bmw::hash512;
  }
  pub mod cubehash {
    pub use crate::cubehash::hash512;
  }
  pub mod echo {
    pub use crate::echo::hash512;
  }
  pub mod groestl {
    pub use crate::groestl::hash512;
  }
  pub mod jh {
    pub use crate::jh::hash512;
  }
  pub mod keccak {
    pub use crate::keccak::hash512;
  }
  pub mod luffa {
    pub use crate::luffa::hash512;
  }
  pub mod shavite {
    pub use crate::shavite::hash512;
  }
  pub mod simd {
    pub use crate::simd::hash512;
  }
  pub mod skein {
    pub use crate::skein::hash512;
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
  let h = simd::hash512(&h);
  let h = echo::hash512(&h);
  let mut out = [0u8; 32];
  out.copy_from_slice(&h[..32]);
  out
}
