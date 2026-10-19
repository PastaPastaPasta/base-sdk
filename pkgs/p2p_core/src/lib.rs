//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash P2P message types for BIP324 encrypted transport.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod bip324;
mod codec;
mod command;
mod error;
#[macro_use]
mod macros;
mod magic;
mod msg;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod short_id;
mod version;

#[doc(hidden)]
pub mod __private {
  pub use dash_primitives;
  pub use dash_types;
}
pub use bip324::{decode_v2, encode_v2};
pub use codec::MAX_P2P_PAYLOAD_SIZE;
pub use command::CommandString;
pub use error::P2pDecodeError;
pub use magic::Magic;
pub use msg::*;
pub use short_id::ShortId;
pub use version::ProtocolVersion;
