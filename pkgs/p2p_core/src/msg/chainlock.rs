//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ChainLock and InstantSend lock messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use dash_pkc::bls::BlsSigBytes;
use dash_primitives::{hash_impl, BlockHash, OutPoint, TxHash, MAX_DIP0001_BLOCK_SIZE};
use dash_types::codec::{decode_vec, BaseCodec, DecodeError, EncodeBuf};
use dash_types::impl_new;
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

codec_p2p! {
/// A ChainLock signature message.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ClSig {
  /// Height of the locked block.
  #[getset(get_copy = "pub")]
  height: i32,
  /// Hash of the locked block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// BLS signature, as read.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl_new! {
/// A deterministic InstantSend lock on a transaction.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IsdLock {
  /// Lock version, read as any value.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Outpoints the locked transaction spends.
  #[getset(get = "pub")]
  inputs: Vec<OutPoint>,
  /// Hash of the locked transaction.
  #[getset(get_copy = "pub")]
  txid: TxHash,
  /// Cycle hash, a block hash.
  #[getset(get_copy = "pub")]
  cycle_hash: BlockHash,
  /// BLS signature, as read.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl_p2p!(IsdLock);

impl BaseCodec for IsdLock {
  /// Decodes an `isdlock`, reading at most [`IsdLock::MAX_INPUTS`] inputs.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      inputs: decode_vec(data, Self::MAX_INPUTS)?,
      txid: TxHash::decode(data)?,
      cycle_hash: BlockHash::decode(data)?,
      sig: BlsSigBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.inputs.encode(buf);
    self.txid.encode(buf);
    self.cycle_hash.encode(buf);
    self.sig.encode(buf);
  }
}

hash_impl!(IsdLock);

impl IsdLock {
  /// The most inputs an `isdlock` carries, one per 41 bytes of the largest
  /// block.
  pub const MAX_INPUTS: usize = MAX_DIP0001_BLOCK_SIZE / 41;
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_num::Hash256;
  use dash_pkc::bls::BLS_SIG_LEN;
  use dash_types::{CompactSize, Hashable};
  use rstest::rstest;
  use serde::Deserialize;

  #[rstest]
  fn corpus_clsig() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainlock");
    let items = corpus.entries::<ClSig>("clsig", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::CLSIG, raw);
      assert_eq!(decoded, Ok(P2pMsg::ClSig(*details)), "{label}: dispatch");
    });
    assert_serde_rt("clsig", &items);
  }

  #[rstest]
  fn corpus_isdlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainlock");
    let items = corpus.entries::<IsdLock>("isdlock", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::ISDLOCK, raw);
      assert_eq!(decoded, Ok(P2pMsg::IsdLock(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("isdlock", &items);
  }

  #[derive(Deserialize)]
  struct InputLimitVector {
    max_inputs: usize,
    version: u8,
    inputs: u32,
    input_hash: TxHash,
    txid: TxHash,
    cycle_hash: BlockHash,
    size: usize,
    hash: Hash256,
  }

  #[rstest]
  fn corpus_isdlock_input_limit() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainlock");
    for v in corpus.vectors::<InputLimitVector>("isdlock_input_limit") {
      assert_eq!(IsdLock::MAX_INPUTS, v.max_inputs);
      let inputs = (0..v.inputs).map(|i| OutPoint::new(v.input_hash, i)).collect();
      let sig = BlsSigBytes::from_bytes([0; BLS_SIG_LEN]);
      let lock = IsdLock::new(v.version, inputs, v.txid, v.cycle_hash, sig);
      let mut raw = Vec::new();
      lock.encode(&mut raw);
      assert_eq!((raw.len(), lock.hash()), (v.size, v.hash), "{} inputs", v.inputs);
      let expected = if v.inputs as usize <= v.max_inputs {
        Ok(lock)
      } else {
        Err(DecodeError::CompactSizeExceedsLimit {
          limit: IsdLock::MAX_INPUTS,
          value: v.inputs.into(),
        })
      };
      assert_eq!(IsdLock::decode(&mut &raw[..]), expected, "{} inputs", v.inputs);
    }
  }

  /// A lock whose input count is `count`, followed by `inputs` outpoints.
  fn isdlock_payload(count: usize, inputs: usize) -> Vec<u8> {
    let mut head = Vec::new();
    1u8.encode(&mut head);
    CompactSize::from(count).encode(&mut head);
    [&head[..], &vec![0x11; inputs * 36], &[0x22; 32 + 32 + 96]].concat()
  }

  #[rstest]
  #[case::at_limit(IsdLock::MAX_INPUTS, IsdLock::MAX_INPUTS, Ok(IsdLock::MAX_INPUTS))]
  #[case::past_limit(
    IsdLock::MAX_INPUTS + 1,
    IsdLock::MAX_INPUTS + 1,
    Err(DecodeError::CompactSizeExceedsLimit { limit: IsdLock::MAX_INPUTS, value: IsdLock::MAX_INPUTS as u64 + 1 })
  )]
  #[case::past_limit_bare(
    IsdLock::MAX_INPUTS + 1,
    0,
    Err(DecodeError::CompactSizeExceedsLimit { limit: IsdLock::MAX_INPUTS, value: IsdLock::MAX_INPUTS as u64 + 1 })
  )]
  fn input_counts_are_bounded(
    #[case] count: usize,
    #[case] inputs: usize,
    #[case] expected: Result<usize, DecodeError>,
  ) {
    let payload = isdlock_payload(count, inputs);
    let decoded = IsdLock::decode(&mut &payload[..]).map(|lock| lock.inputs.len());
    assert_eq!(decoded, expected);
  }
}
