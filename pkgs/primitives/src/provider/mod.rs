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
use crate::types::NetInfo;

use dash_types::codec::{BaseCodec, EncodeBuf};

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

/// Writes the network info the payload version selects. Validation
/// guarantees the variant matches the version.
pub(super) fn write_net_info(buf: &mut impl EncodeBuf, net_info: &NetInfo, version: ProTxVersion) {
  if version >= ProTxVersion::CoreV24 {
    if let NetInfo::Extended(ext) = net_info {
      ext.encode(buf);
    }
  } else if let NetInfo::Legacy(svc) = net_info {
    svc.encode(buf);
  }
}
