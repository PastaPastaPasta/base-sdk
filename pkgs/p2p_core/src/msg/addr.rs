//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address messages.

use super::version::ServiceFlags;
use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use dash_primitives::{hash_impl, AddrV2, ServiceV1};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{CompactSize, Numeric};

use core::fmt;

codec_p2p! {
/// V1 address announcement carrying timestamped addresses.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Addr {
  /// Timestamped v1 address entries.
  pub addrs: Vec<TimestampedAddr>,
}
}

/// BIP155 timestamped v2 address entry used in `addrv2` messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Entry {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services.
  pub services: ServiceFlags,
  /// Network address.
  pub addr: AddrV2,
  /// Port number.
  pub port: u16,
}

impl BaseCodec for AddrV2Entry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let time = u32::decode(data)?;
    let services = ServiceFlags(CompactSize::decode_unbounded(data)?.to_base());
    let addr = AddrV2::decode(data)?;
    let port = codec::read_u16_be(data)?;
    Ok(Self {
      time,
      services,
      addr,
      port,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.time.encode(buf);
    CompactSize::from(self.services.0).encode(buf);
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl_p2p!(AddrV2Entry);

hash_impl!(AddrV2Entry);

impl fmt::Display for AddrV2Entry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}:{}", self.addr.network(), self.port)
  }
}

codec_p2p! {
/// BIP155 v2 address announcement.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Msg {
  /// BIP155 address entries.
  pub addrs: Vec<AddrV2Entry>,
}
}

codec_p2p! {
/// Timestamped v1 address entry used in `addr` messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TimestampedAddr {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services.
  pub services: ServiceFlags,
  /// Network address.
  pub addr: ServiceV1,
}
}
