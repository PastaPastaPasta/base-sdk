//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Provider transaction payloads.

mod prodistx;
mod proregtx;
mod proupregtx;
mod prouprevtx;
mod proupservtx;
mod proupsharedregtx;
mod proupsharetx;
mod share;
mod sig;
mod version;

#[cfg(feature = "serde")]
pub(crate) use self::sig::compact_hex;

pub use self::prodistx::ProDisTx;
pub use self::proregtx::ProRegTx;
pub use self::proupregtx::ProUpRegTx;
pub use self::prouprevtx::ProUpRevTx;
pub use self::proupservtx::ProUpServTx;
pub use self::proupsharedregtx::ProUpSharedRegTx;
pub use self::proupsharetx::ProUpShareTx;
pub use self::share::{CollateralShare, PayoutShare};
pub use self::sig::{CollateralSig, DissolveSig, EcdsaRecSigArray, JoinSig, OperatorSig, OwnerSig, SharedRegistrarSig};
pub use self::version::ProTxVersion;

pub use dash_pkc::__private::__EddsaPkHash as PlatformNodeId;
