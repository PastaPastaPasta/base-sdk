//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared types and macros for the Dash SDK.

#![no_std]

extern crate alloc;
extern crate self as dash_types;
#[cfg(feature = "std")]
extern crate std;

mod entity;
mod hex;
mod macros;
mod numeric;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod secret;
mod traits;

#[doc(hidden)]
pub mod __deps {
  pub use zeroize;
}
#[cfg(feature = "serde")]
pub mod serialize;

pub use hex::ParseHexError;
pub use macros::qtypestr;
pub use numeric::Numeric;
pub use traits::{Checkable, Hashable};

cfg_if::cfg_if! {
  if #[cfg(feature = "codec")] {
    #[allow(unused_macros, reason = "used by feature-gated submodules")]
    mod adapters;
    mod compact;
    mod core_bool;

    pub mod codec;
    pub mod type_id;

    pub use compact::CompactSize;
    pub use core_bool::CoreBool;
    pub use entity::{VecDecoder, VecEncoder, MAX_SER_SIZE};
    pub use secret::{ArrDecoder, ArrEncoder, ArrayBuf, MAX_ARR_SIZE};
  }
}

#[doc(hidden)]
pub mod __private {
  #[cfg(feature = "bitcoin-primitives")]
  pub use crate::adapters::bitcoin_primitives::ScriptHash as __ScriptHash;
  pub use crate::hex::{read_hex as __read_hex, write_hex as __write_hex};

  #[cfg(feature = "codec")]
  pub use bitcoin_consensus_encoding;
  pub use hex_conservative;
  #[cfg(feature = "serde")]
  pub use serde;
  pub use subtle;
}
