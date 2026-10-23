//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address parameters.

use dash_types::type_id::Unencodable;

/// Network address encoding parameters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct AddrParams {
  /// P2PKH address version byte.
  pub pubkey_addr: u8,
  /// P2SH address version byte.
  pub script_addr: u8,
  /// WIF private key version byte.
  pub secret_key: u8,
  /// BIP32 extended public key prefix.
  pub ext_pubkey: [u8; 4],
  /// BIP32 extended secret key prefix.
  pub ext_secret: [u8; 4],
  /// BIP44 coin type index.
  pub bip44_idx: u32,
  /// Bech32m human-readable part of DIP-18 Platform addresses.
  pub bech32_hrp: &'static str,
}
