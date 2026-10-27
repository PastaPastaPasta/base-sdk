//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash network and address types.

#[expect(clippy::same_name_method, reason = "trait impl delegates to method")]
mod addrv1;
#[expect(clippy::same_name_method, reason = "trait impl delegates to method")]
mod addrv2;
mod netaddr;
mod netinfo;
mod util;

pub use addrv1::{AddrV1, ServiceV1};
pub use addrv2::{AddrV2, ServiceV2};
pub use netaddr::{is_bad_port, NetAddr, NetAddrError, NetworkType};
pub use netinfo::{NIEntry, NIEntryCode, NIError, NIPurpose, NITrait, NetInfo, NetInfoV1, NetInfoV2};
