//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Development and test utilities.

#![no_std]
#![expect(clippy::panic, reason = "development crate")]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod encode;
mod lambda;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

pub use encode::{arr_from_hex, vec_from_hex};
pub use lambda::{check_sptx, check_tx, check_wire};

cfg_if::cfg_if! {
  if #[cfg(all(feature = "std", feature = "serde"))] {
    #[doc(hidden)]
    mod __private {
      pub use serde_json::Value;
    }
    mod corpus;
    mod json;

    pub use __private::Value;
    pub use corpus::{assert_serde_rt, Corpus};
    pub use encode::assert_cbor_raw;
    pub use json::{assert_json_rt, from_json, from_json_slice, json_rejects, to_json};
  }
}
