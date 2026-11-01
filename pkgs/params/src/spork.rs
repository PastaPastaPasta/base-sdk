//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Spork signers as the reference implementation's startup resolves them.

use crate::prelude::*;

use base58ck::decode_check;
use dash_num::Hash160;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use dash_types::Numeric;

/// The keys that sign sporks, the chain's default address with
/// `-sporkaddr` and `-minsporkkeys` applied. Verifying sporks is not this
/// crate's job.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[non_exhaustive]
pub struct SporkSigners {
  /// Signer key IDs. At v23.1 a set (ascending, distinct), at v24 one key.
  pub key_ids: Vec<Hash160>,
  /// Signatures a spork needs, at v23.1 only.
  pub min_spork_keys: Option<i32>,
  /// The startup warning when v24 is given several `-sporkaddr` values.
  pub warning: Option<String>,
}

/// Whether the reference's Base58 decoder skips `c` around an address.
const fn is_base58_space(c: char) -> bool {
  matches!(c, ' ' | '\x0c' | '\n' | '\r' | '\t' | '\x0b')
}

/// The key ID of `address` if the reference reads it as a P2PKH address
/// with version byte `pubkey_addr`.
///
/// The reference refuses a NUL and skips surrounding whitespace. From v24
/// it reads a string starting with the Platform HRP `platform_hrp` (in any
/// case) as bech32m, never as a key.
pub(crate) fn spork_key_id(address: &str, pubkey_addr: u8, platform_hrp: Option<&str>) -> Option<Hash160> {
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
  let data = decode_check(address.trim_matches(is_base58_space)).ok()?;
  let (&version, hash) = data.split_first()?;
  let hash: [u8; 20] = hash.try_into().ok()?;
  (version == pubkey_addr).then(|| Hash160::from_base(hash))
}
