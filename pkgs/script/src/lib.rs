//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scripting and addressing.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "codec")]
mod addrs;
mod opcode;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod sigops;

#[cfg(feature = "codec")]
pub use addrs::Recipient;
#[cfg(feature = "codec")]
pub use dash_pkc::__private::__EcdsaPkHash as PubKeyHash;
#[cfg(feature = "codec")]
pub use dash_types::__private::__ScriptHash as ScriptHash;
pub use opcode::Opcode;
pub use sigops::legacy_sigop_count;
