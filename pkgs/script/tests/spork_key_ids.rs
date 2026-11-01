//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! `dash-params` decodes `-sporkaddr` with its own Base58Check reader, which
//! must read P2PKH addresses as [`Recipient::from_base58c`] does.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_params::{ChainOption, ChainParamsBuilder, Network, ParamsError, Release};
use dash_script::{PubKeyHash, Recipient};
use dash_types::Numeric;
use rstest::rstest;

/// The spork key ID `dash-params` reads from `address`, or `None` if it
/// refuses the address.
fn spork_key_id(network: Network, release: Release, address: &str) -> Option<[u8; 20]> {
  match ChainParamsBuilder::new(network, release)
    .arg(ChainOption::SporkAddr, address)
    .build()
  {
    Ok(setup) => Some(*setup.spork_signers.key_ids[0].as_bytes()),
    Err(err) => {
      assert_eq!(err, ParamsError::SporkAddress, "{address}");
      None
    }
  }
}

/// The P2PKH key ID `dash-script` reads from `address` on `network`.
fn recipient_key_id(network: Network, address: &str) -> Option<[u8; 20]> {
  match Recipient::from_base58c(address, network.addr())? {
    Recipient::PubKeyHash(hash) => Some(*hash.as_bytes()),
    _ => None,
  }
}

/// 20-byte hashes, the extremes and a fixed pseudo-random spread.
fn hashes() -> Vec<[u8; 20]> {
  let mut state = 0x2545_f491_4f6c_dd1d_u64;
  let mut hashes = vec![[0; 20], [0xff; 20]];
  for _ in 0..32 {
    hashes.push(core::array::from_fn(|_| {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state.to_le_bytes()[0]
    }));
  }
  hashes
}

#[rstest]
fn spork_addresses_decode_as_recipients(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let addr = network.addr();
  let mut accepted = 0;
  for hash in hashes() {
    for version in [addr.pubkey_addr, addr.script_addr, addr.secret_key, 0, 0xff] {
      let address = PubKeyHash::from_lendian(hash).to_base58c(version);
      let ours = spork_key_id(network, release, &address);
      assert_eq!(ours, recipient_key_id(network, &address), "{address}");
      assert_eq!(ours.is_some(), version == addr.pubkey_addr, "{address}");
      accepted += usize::from(ours.is_some());
      // Both refuse a corrupted checksum.
      let mut corrupted = address.clone();
      let last = corrupted.pop().unwrap();
      corrupted.push(if last == '1' { '2' } else { '1' });
      assert_eq!(spork_key_id(network, release, &corrupted), None, "{corrupted}");
      assert_eq!(recipient_key_id(network, &corrupted), None, "{corrupted}");
    }
  }
  assert_eq!(accepted, hashes().len());
  for other in ["", "1", "not an address", "11111111111111111111111111111111111111"] {
    assert_eq!(spork_key_id(network, release, other), None, "{other}");
    assert_eq!(recipient_key_id(network, other), None, "{other}");
  }
}
