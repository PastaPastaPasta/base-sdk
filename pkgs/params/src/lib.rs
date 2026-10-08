//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Chain parameters for Dash, equal to Dash Core's `CChainParams`.
//!
//! [`ChainParamsBuilder`] builds the parameters of a [`NetworkKind`] at a
//! [`Release`], applying Core's command-line overrides with Core's errors.
//!
//! One deviation is deliberate. Core accepts a negative regtest height from
//! `-vbparams`, `-dip3params` or `-budgetparams`; heights here are unsigned,
//! so a height still negative in the final parameters is refused.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod builder;
mod data;
mod devnet;
mod error;
mod genesis;
mod llmq;
mod mainnet;
mod network;
mod parse;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod regtest;
mod spork;
mod testnet;
mod types;

pub use builder::{ChainOption, ChainParamsBuilder};
pub use error::{ParamsError, VbField};
pub use llmq::{LlmqParams, AVAILABLE_LLMQS, MAX_LLMQ_SIZE};
pub use network::{NetworkKind, Release};
pub use types::*;
