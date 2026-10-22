//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of work chained hash tests.

use dash_pow::__deps::digest::Digest;
use dash_pow::X11;
use hex_conservative::hex;
use rstest::rstest;

#[rstest]
#[case::empty(&[], hex!("51b572209083576ea221c27e62b4e22063257571ccb6cc3dc3cd17eb67584eba"))]
#[case::single_zero(&[0u8], hex!("ad4015a1059886781a796efe2326c9e6beb07bcf847f4897e0f8a3fa24004024"))]
fn known_hash(#[case] input: &[u8], #[case] expected: [u8; 32]) {
  let got: [u8; 32] = X11::digest(input).into();
  assert_eq!(got, expected);
}

/// Feeding the message in pieces, or with empty updates, matches one update.
#[rstest]
#[case::empty(0)]
#[case::header(80)]
#[case::two_blocks(256)]
#[case::long(1000)]
fn chunked_updates(#[case] len: usize) {
  let input: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
  let expected = X11::digest(&input);

  let mut byte_wise = X11::new();
  for byte in &input {
    byte_wise.update(core::slice::from_ref(byte));
  }
  assert_eq!(byte_wise.finalize(), expected, "byte by byte");

  for cut in 0..=len {
    let mut hasher = X11::new();
    hasher.update(&input[..cut]);
    hasher.update(&input[cut..]);
    assert_eq!(hasher.finalize(), expected, "cut at {cut}");
  }

  let mut empty_updates = X11::default();
  empty_updates.update([]);
  empty_updates.update(&input);
  empty_updates.update([]);
  assert_eq!(empty_updates.finalize(), expected, "empty updates");
}

/// Hashing fits a 128 KiB thread stack in debug builds too. At -O0 a forced
/// inline keeps its callee's locals in the caller's frame, and a `const`
/// table is copied per lookup, so either regression overflows here.
#[rstest]
#[case::empty(&[], hex!("51b572209083576ea221c27e62b4e22063257571ccb6cc3dc3cd17eb67584eba"))]
#[case::single_zero(&[0u8], hex!("ad4015a1059886781a796efe2326c9e6beb07bcf847f4897e0f8a3fa24004024"))]
fn fits_128k_thread_stack(#[case] input: &'static [u8], #[case] expected: [u8; 32]) -> std::io::Result<()> {
  let handle = std::thread::Builder::new()
    .stack_size(128 * 1024)
    .spawn(move || X11::digest(input))?;
  let digest: Option<[u8; 32]> = handle.join().ok().map(Into::into);
  assert_eq!(digest, Some(expected));
  Ok(())
}
