//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Message decoders reserve no more than the payload can back: a count the
//! bytes cannot fill fails without an allocation in proportion to it.

#![cfg(feature = "std")]
#![expect(unsafe_code, reason = "a counting test allocator")]

use dash_p2p_core::{CommandString, P2pMsg, ProtoCtx, ProtocolVersion};
use dash_pkc::bls::BlsCtx;
use rstest::rstest;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// Records the largest single allocation each thread makes.
struct Peak;

thread_local! {
  static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn record(size: usize) {
  let _ = LARGEST.try_with(|c| c.set(c.get().max(size)));
}

// SAFETY: every call is forwarded unchanged to the system allocator.
unsafe impl GlobalAlloc for Peak {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    record(layout.size());
    // SAFETY: the caller's contract is passed through.
    unsafe { System.alloc(layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    // SAFETY: the caller's contract is passed through.
    unsafe { System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    record(new_size);
    // SAFETY: the caller's contract is passed through.
    unsafe { System.realloc(ptr, layout, new_size) }
  }
}

#[global_allocator]
static ALLOCATOR: Peak = Peak;

/// `MAX_SIZE`, the largest count Core's `ReadCompactSize` accepts.
const MAX_SIZE: [u8; 5] = [0xfe, 0x00, 0x00, 0x00, 0x02];

/// A payload: `prefix` bytes, a `MAX_SIZE` count, then 64 zero bytes.
fn hostile(prefix: usize) -> Vec<u8> {
  let mut out = vec![0u8; prefix];
  out.extend(MAX_SIZE);
  out.extend([0u8; 64]);
  out
}

/// Each command with a `MAX_SIZE` count where its decoder reads one.
#[rstest]
#[case::block_txs("block", hostile(80))]
#[case::tx_inputs("tx", hostile(4))]
#[case::cmpctblock_short_ids("cmpctblock", hostile(88))]
#[case::cmpctblock_prefilled("cmpctblock", { let mut p = vec![0u8; 89]; p.extend(MAX_SIZE); p.extend([0; 64]); p })]
#[case::getblocktxn("getblocktxn", hostile(32))]
#[case::blocktxn("blocktxn", hostile(32))]
#[case::getblocks("getblocks", hostile(4))]
#[case::getheaders2("getheaders2", hostile(4))]
#[case::filterload("filterload", hostile(0))]
#[case::filteradd("filteradd", hostile(0))]
#[case::headers2_8000("headers2", { let mut p = vec![0xfd, 0x40, 0x1f]; p.extend([0u8; 64]); p })]
#[case::headers_2000("headers", { let mut p = vec![0xfd, 0xd0, 0x07]; p.extend([0u8; 64]); p })]
#[case::isdlock_inputs("isdlock", hostile(1))]
#[case::spork_sig("spork", hostile(20))]
#[case::getqrinfo_bases("getqrinfo", hostile(0))]
#[case::qfcommit_signers("qfcommit", hostile(35))]
#[case::mnlistdiff_merkle_hashes("mnlistdiff", hostile(70))]
#[case::qrinfo_active_members("qrinfo", hostile(4))]
#[case::qrinfo_skip_list("qrinfo", hostile(5))]
fn a_count_the_payload_cannot_fill_allocates_little(#[case] cmd: &str, #[case] payload: Vec<u8>) {
  let ctx = ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC);
  LARGEST.with(|c| c.set(0));
  let r = P2pMsg::decode_with_policy(&CommandString::from_static(cmd), &payload, &ctx);
  let largest = LARGEST.with(Cell::get);
  assert!(r.is_err(), "{cmd}: {r:?}");
  assert!(
    largest <= 16 * 1024,
    "{cmd}: allocated {largest} bytes for a {}-byte payload",
    payload.len()
  );
}

/// Whether `T`'s own codec rejects the payload.
fn rejects<T: dash_types::codec::BaseCodec>(payload: &[u8]) -> bool {
  T::decode(&mut &payload[..]).is_err()
}

/// Messages Core sends but has no handler for decode with their own codec.
#[rstest]
#[case::merkleblock_hashes(rejects::<dash_p2p_core::MerkleBlock>, hostile(84))]
#[case::cfilter_bytes(rejects::<dash_p2p_core::CFilter>, hostile(33))]
#[case::cfheaders_hashes(rejects::<dash_p2p_core::CFHeaders>, hostile(65))]
#[case::cfcheckpt_hashes(rejects::<dash_p2p_core::CFCheckpt>, hostile(33))]
fn send_only_codecs_allocate_little(#[case] decode: fn(&[u8]) -> bool, #[case] payload: Vec<u8>) {
  LARGEST.with(|c| c.set(0));
  let rejected = decode(&payload);
  let largest = LARGEST.with(Cell::get);
  assert!(rejected);
  assert!(largest <= 16 * 1024, "allocated {largest} bytes");
}
