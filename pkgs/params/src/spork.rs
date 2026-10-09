//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Spork signer addresses as Core's startup reads them.

use dash_script::{AddrParams, PubKeyHash, Recipient};

/// Core's `IsSpace`: the characters `DecodeBase58` skips around an address.
fn is_core_space(c: char) -> bool {
  matches!(c, ' ' | '\x0c' | '\n' | '\r' | '\t' | '\x0b')
}

/// The key ID of `address` if Core's `DecodeDestination` reads it as a P2PKH
/// address under `addr` (`CSporkManager::SetSporkAddress`).
///
/// Core rejects a NUL, skips surrounding whitespace, and from v24 reads a
/// string starting with the Platform HRP `platform_hrp` (any case) as bech32,
/// never as a key.
pub(crate) fn spork_key_id(address: &str, addr: &AddrParams, platform_hrp: Option<&str>) -> Option<PubKeyHash> {
  if address.contains('\0') {
    return None;
  }
  let bytes = address.as_bytes();
  if platform_hrp.is_some_and(|hrp| {
    bytes
      .get(..hrp.len())
      .is_some_and(|p| p.eq_ignore_ascii_case(hrp.as_bytes()))
  }) {
    return None;
  }
  match Recipient::from_base58c(address.trim_matches(is_core_space), addr)? {
    Recipient::PubKeyHash(hash) => Some(hash),
    _ => None,
  }
}
