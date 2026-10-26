//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Consensus-compatible numeric types.
//!
//! Provides hash blob types [`Hash256`], [`Hash160`] and the [`Arith256`]
//! arithmetic integer type.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[expect(clippy::same_name_method, reason = "trait impl delegates to method")]
mod arith256;
mod compact;
mod hash;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod util;

#[doc(hidden)]
pub mod __deps {
  pub use dash_types;
}
#[doc(hidden)]
pub mod __private {
  #[cfg(feature = "codec")]
  pub use bitcoin_consensus_encoding;
  #[cfg(feature = "serde")]
  pub use serde;
}

pub use arith256::Arith256;
pub use compact::{CompactTarget, DecodedTarget};
pub use hash::{Hash160, Hash256, HashBlob};
