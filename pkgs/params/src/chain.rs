//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Chain parameters of a network.

use crate::{AddrParams, Checkpoint, ConsensusParams, GenesisParams};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// P2P network message start bytes (magic).
pub type MessageStart = [u8; 4];

/// Transaction statistics for chain sync progress estimation.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ChainTxData {
  /// Unix timestamp of the last known block.
  pub timestamp: i64,
  /// Total number of transactions in the chain.
  pub tx_count: i64,
  /// Estimated transactions per second after that timestamp.
  pub tx_rate: f64,
}

/// Complete chain parameters for a network.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ChainParams {
  /// Consensus rules for this chain.
  pub consensus: ConsensusParams,
  /// Descriptor of the genesis block.
  pub genesis: GenesisParams,
  /// Four-byte magic identifying network messages.
  pub message_start: MessageStart,
  /// Default P2P listen port.
  pub default_port: u16,
  /// Default Platform P2P port.
  pub default_platform_p2p_port: u16,
  /// Default Platform HTTP API port.
  pub default_platform_http_port: u16,
  /// Default JSON-RPC port.
  pub rpc_port: u16,
  /// Tor onion service target port.
  pub onion_service_target_port: u16,
  /// DNS seed hostnames for peer discovery.
  pub dns_seeds: &'static [&'static str],
  /// Address encoding parameters.
  pub addr_params: AddrParams,
  /// Human-readable network identifier string.
  pub network_id: &'static str,
  /// Whether this is a test network.
  pub is_test_chain: bool,
  /// Minimum participants for a CoinJoin session.
  pub pool_min_participants: i32,
  /// Maximum participants for a CoinJoin session.
  pub pool_max_participants: i32,
  /// Address of the key that signs sporks.
  pub spork_address: &'static str,
  /// Number of blocks in a credit-pool accounting period.
  pub credit_pool_period_blocks: i32,
  /// Hard-coded checkpoints for fast validation.
  pub checkpoints: &'static [Checkpoint],
  /// Transaction statistics for progress estimation.
  pub chain_tx_data: ChainTxData,
}
