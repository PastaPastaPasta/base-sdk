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
mod shares;
mod sig;
mod version;

use crate::sptx::{MnType, ProTxInvalid};
use crate::types::{NetInfo, NetInfoV1, NetInfoV2};

use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};

#[cfg(feature = "serde")]
pub(crate) use self::sig::compact_hex;

pub use self::prodistx::ProDisTx;
pub use self::proregtx::ProRegTx;
pub use self::proupregtx::ProUpRegTx;
pub use self::prouprevtx::ProUpRevTx;
pub use self::proupservtx::ProUpServTx;
pub use self::proupsharedregtx::ProUpSharedRegTx;
pub use self::proupsharetx::ProUpShareTx;
pub use self::shares::{CollateralShare, CompactSig, PayoutShare, COMPACT_SIG_LEN};
pub use self::sig::{CollateralSig, OperatorSig, OwnerSig};
pub use self::version::ProTxVersion;

pub use dash_pkc::__private::__EddsaPkHash as PlatformNodeId;

/// Checks that platform fields are consistent with mn_type and version.
pub(super) fn check_platform_fields(
  mn_type: MnType,
  version: ProTxVersion,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) -> Option<ProTxInvalid> {
  if mn_type == MnType::Evo {
    if platform_node_id.is_none() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
    if version < ProTxVersion::ExtAddr {
      if platform_p2p_port.is_none() || platform_http_port.is_none() {
        return Some(ProTxInvalid::BadPlatformFields);
      }
    } else if platform_p2p_port.is_some() || platform_http_port.is_some() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
  } else if platform_node_id.is_some() || platform_p2p_port.is_some() || platform_http_port.is_some() {
    return Some(ProTxInvalid::BadPlatformFields);
  }
  None
}

/// The platform node id, P2P port and HTTP port of an Evo node.
pub(super) type PlatformFields = (Option<PlatformNodeId>, Option<u16>, Option<u16>);

/// Reads the platform fields that follow the inputs hash for Evo nodes.
pub(super) fn read_platform_fields(
  data: &mut &[u8],
  mn_type: MnType,
  version: ProTxVersion,
) -> Result<PlatformFields, DecodeError> {
  if mn_type != MnType::Evo {
    return Ok((None, None, None));
  }
  let node_id = PlatformNodeId::decode(data)?;
  if version < ProTxVersion::ExtAddr {
    Ok((Some(node_id), Some(u16::decode(data)?), Some(u16::decode(data)?)))
  } else {
    Ok((Some(node_id), None, None))
  }
}

/// Writes the platform fields as [`read_platform_fields`] reads them.
pub(super) fn write_platform_fields(
  buf: &mut impl EncodeBuf,
  mn_type: MnType,
  version: ProTxVersion,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) {
  if mn_type == MnType::Evo {
    platform_node_id.unwrap_or_default().encode(buf);
    if version < ProTxVersion::ExtAddr {
      platform_p2p_port.unwrap_or(0).encode(buf);
      platform_http_port.unwrap_or(0).encode(buf);
    }
  }
}

/// Reads the network info a version carries, extended from v3.
pub(super) fn read_net_info(data: &mut &[u8], version: ProTxVersion) -> Result<NetInfo, DecodeError> {
  if version >= ProTxVersion::ExtAddr {
    Ok(NetInfo::Extended(NetInfoV2::decode(data)?))
  } else {
    Ok(NetInfo::Legacy(NetInfoV1::decode(data)?))
  }
}

/// Writes the network info as [`read_net_info`] reads it. Validation
/// guarantees the variant matches the version.
pub(super) fn write_net_info(buf: &mut impl EncodeBuf, net_info: &NetInfo, version: ProTxVersion) {
  if version >= ProTxVersion::ExtAddr {
    if let NetInfo::Extended(ext) = net_info {
      ext.encode(buf);
    }
  } else if let NetInfo::Legacy(svc) = net_info {
    svc.encode(buf);
  }
}
