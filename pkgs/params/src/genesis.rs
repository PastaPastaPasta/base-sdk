//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis block descriptor.

use bitcoin_units::Amount;
use dash_types::type_id::Unencodable;
use hex_conservative::hex;

/// Fields that define a genesis block with a single coinbase transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct GenesisParams {
  /// Block version.
  pub version: i32,
  /// Block timestamp (unix epoch seconds).
  pub time: u32,
  /// Compact difficulty target.
  pub bits: u32,
  /// Nonce used for proof-of-work.
  pub nonce: u32,
  /// Input script of the coinbase transaction.
  pub script_sig: &'static [u8],
  /// Output script of the coinbase transaction.
  pub script_pubkey: &'static [u8],
  /// Value of the coinbase output.
  pub reward: Amount,
}

impl GenesisParams {
  /// Coinbase input script shared by every network's genesis block.
  pub(crate) const COINBASE_SCRIPT_SIG: &[u8] = &hex!(concat!(
    "04ffff001d01044c5957697265642030392f4a616e2f323031342054686520",
    "4772616e64204578706572696d656e7420476f6573204c6976653a204f7665",
    "7273746f636b2e636f6d204973204e6f7720416363657074696e6720426974",
    "636f696e73"
  ));

  /// Coinbase output script shared by every network's genesis block.
  pub(crate) const COINBASE_SCRIPT_PUBKEY: &[u8] = &hex!(concat!(
    "41040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4",
    "d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070",
    "ac7b03a9ac"
  ));
}
