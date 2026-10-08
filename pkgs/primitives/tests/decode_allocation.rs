//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Decoders reserve no more than the bytes they are given can back, in Core's
//! batches: a count the input cannot fill costs at most one batch.

#![cfg(feature = "std")]
#![expect(unsafe_code, reason = "a counting test allocator")]
#![expect(clippy::unwrap_used, reason = "test code")]

use dash_pkc::bls::BlsCtx;
use dash_primitives::{NetInfoV2, Transaction};
use dash_types::codec::BaseCodec;
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

/// The largest single allocation `f` makes on this thread.
fn largest_allocation<R>(f: impl FnOnce() -> R) -> (R, usize) {
  LARGEST.with(|c| c.set(0));
  let out = f();
  (out, LARGEST.with(Cell::get))
}

fn compact_size(n: usize, out: &mut Vec<u8>) {
  let n = u32::try_from(n).unwrap();
  if n < 0xfd {
    out.push(n as u8);
  } else {
    out.push(0xfe);
    out.extend(n.to_le_bytes());
  }
}

/// A NetInfoV2 of `len` bytes: version 1, the count, then zeros. A zero
/// group is purpose 0 with no entries, so `count = left / 2` is all valid.
fn net_info(len: usize, count: impl FnOnce(usize) -> usize) -> Vec<u8> {
  let left = len - 1 - 5;
  let mut out = vec![1];
  out.push(0xfe);
  out.extend(u32::try_from(count(left)).unwrap().to_le_bytes());
  out.resize(len, 0);
  out
}

/// A type-2 (ProUpServTx) transaction with a v3 payload of about 3 MiB whose
/// NetInfoV2 claims a group per byte left (BS4a r2 review, N-2).
fn pro_up_serv_tx() -> (Vec<u8>, usize) {
  let len = 3 * 1024 * 1024 - 200;
  // u16 version 3, u16 type 0, proTxHash, then the NetInfoV2.
  let mut payload = vec![3, 0, 0, 0];
  payload.extend([0; 32]);
  payload.extend(net_info(len - payload.len(), |left| left));
  let mut tx = Vec::new();
  tx.extend(((2u32 << 16) | 3).to_le_bytes());
  tx.push(1);
  tx.extend([0x11; 32]);
  tx.extend(0u32.to_le_bytes());
  tx.push(0);
  tx.extend(u32::MAX.to_le_bytes());
  tx.push(1);
  tx.extend(0i64.to_le_bytes());
  tx.push(0);
  tx.extend(0u32.to_le_bytes());
  compact_size(payload.len(), &mut tx);
  tx.extend(&payload);
  (tx, payload.len())
}

/// The review's witness reserved 100,655,552 bytes, 32 times its payload.
#[rstest]
fn special_payload_reserves_at_most_its_size() {
  let (raw, len) = pro_up_serv_tx();
  let tx = Transaction::decode(&mut &raw[..]).unwrap();
  let (decoded, largest) = largest_allocation(|| tx.decode_payload(BlsCtx::BASIC));
  assert!(matches!(decoded, Some(Err(_))), "{decoded:?}");
  assert!(largest <= len, "largest allocation {largest} for a {len}-byte payload");
}

/// Every group valid: Core's map keeps one, so the decoder holds one.
#[rstest]
#[case::count_beyond_the_bytes(|left: usize| left)]
#[case::every_group_valid(|left: usize| left / 2)]
fn net_info_groups_are_bound_by_the_bytes(#[case] count: fn(usize) -> usize) {
  let raw = net_info(3 * 1024 * 1024, count);
  let (decoded, largest) = largest_allocation(|| NetInfoV2::decode(&mut &raw[..]));
  assert!(
    largest <= raw.len(),
    "largest allocation {largest} for {} bytes",
    raw.len()
  );
  if let Ok(info) = decoded {
    assert_eq!(info.entries.len(), 1);
  }
}

/// Core's `MAX_VECTOR_ALLOCATE`, the most `Vec<T>` reserves at a time.
const MAX_VECTOR_ALLOCATE: usize = 5_000_000;

/// A vector of byte strings, 24 bytes each in memory and 1 on the wire, whose
/// first element has a non-canonical length. `Vec<T>` reserves exactly one
/// batch of at most Core's size beyond the items read, and no more items than
/// the bytes left can hold.
#[rstest]
fn vector_reservation_is_bound_as_core() {
  let len = 3 * 1024 * 1024;
  let mut raw = vec![0xfe];
  raw.extend(u32::try_from(len - 5).unwrap().to_le_bytes());
  raw.extend([0xfd, 0x00, 0x00]);
  raw.resize(len, 0);
  let (decoded, largest) = largest_allocation(|| Vec::<Vec<u8>>::decode(&mut &raw[..]));
  assert!(decoded.is_err());
  assert!(largest <= MAX_VECTOR_ALLOCATE, "largest allocation {largest}");
}
