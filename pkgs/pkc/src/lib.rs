//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public-key cryptography for Dash.

#![no_std]

extern crate alloc;
extern crate self as dash_pkc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(all(
  not(any(doc, feature = "portable")),
  feature = "bls",
  target_arch = "x86_64",
  not(target_feature = "adx")
))]
compile_error!("dash-pkc requires ADX with `bls`, build with `-C target-feature=+adx` or enable `portable`");

#[cfg(feature = "bls")]
mod aes_cbc;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
#[cfg(test)]
mod tests;

pub mod bls;
pub mod ecdsa;
pub mod eddsa;

#[doc(hidden)]
pub mod __deps {
  #[cfg(feature = "bls")]
  pub use blst;
  pub use dash_num;
  pub use dash_types;
  #[cfg(feature = "eddsa")]
  pub use ed25519_dalek;
  #[cfg(feature = "bls")]
  pub use ff;
  #[cfg(feature = "bls")]
  pub use group;
  #[cfg(any(feature = "bls", feature = "ecdsa", feature = "eddsa"))]
  pub use rand_core;
  #[cfg(feature = "ecdsa")]
  pub use secp256k1;
  #[cfg(feature = "bls")]
  pub use subtle;
  pub use zeroize;
}

#[cfg(feature = "codec")]
#[doc(hidden)]
pub mod __private {
  pub use crate::ecdsa::EcdsaPkHash as __EcdsaPkHash;
  pub use crate::eddsa::EddsaPkHash as __EddsaPkHash;
}
