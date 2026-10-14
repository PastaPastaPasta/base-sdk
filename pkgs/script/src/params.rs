//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address parameters.

use crate::AddrParams;

/// Mainnet address parameters.
pub const MAINNET: AddrParams = AddrParams {
  pubkey_addr: 76,                      // addresses start with 'X'
  script_addr: 16,                      // addresses start with '7'
  secret_key: 204,                      // keys start with '7' or 'X'
  ext_pubkey: [0x04, 0x88, 0xB2, 0x1E], // xpub
  ext_secret: [0x04, 0x88, 0xAD, 0xE4], // xprv
  bip44_idx: 5,
};

/// Testnet address parameters.
pub const TESTNET: AddrParams = AddrParams {
  pubkey_addr: 140,                     // addresses start with 'y'
  script_addr: 19,                      // addresses start with '8' or '9'
  secret_key: 239,                      // keys start with '9' or 'c'
  ext_pubkey: [0x04, 0x35, 0x87, 0xCF], // tpub
  ext_secret: [0x04, 0x35, 0x83, 0x94], // tprv
  bip44_idx: 1,
};

/// Regtest address parameters.
pub const REGTEST: AddrParams = AddrParams {
  pubkey_addr: 140,                     // addresses start with 'y'
  script_addr: 19,                      // addresses start with '8' or '9'
  secret_key: 239,                      // keys start with '9' or 'c'
  ext_pubkey: [0x04, 0x35, 0x87, 0xCF], // tpub
  ext_secret: [0x04, 0x35, 0x83, 0x94], // tprv
  bip44_idx: 1,
};
