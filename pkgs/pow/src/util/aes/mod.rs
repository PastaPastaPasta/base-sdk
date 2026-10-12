//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES round primitives for Echo, Groestl, and SHAvite.

#[cfg(all(feature = "simd", target_arch = "aarch64", not(feature = "portable")))]
#[expect(unsafe_code, reason = "intrinsics")]
pub(crate) mod aarch64;
#[cfg(all(feature = "simd", target_arch = "x86_64", not(feature = "portable")))]
#[expect(unsafe_code, reason = "intrinsics")]
mod amd64;
pub(crate) mod consts;
#[cfg(any(test, feature = "simd"))]
pub(crate) mod cpu;
mod scalar;
#[cfg(feature = "simd")]
pub(crate) mod simd;

#[cfg(test)]
pub(crate) use scalar::sub_bytes;
pub(crate) use scalar::{round, round_nk};

#[cfg(test)]
mod tests {
  use super::consts::{SBOX, T};
  use super::{cpu, round, round_nk, sub_bytes};

  /// AES round on all-zero state+key.
  #[test]
  fn spot_check_rnd_zeroed() {
    let result = round(&[0; 4], &[0; 4]);
    assert_eq!(result, [0x63636363; 4]);
  }

  /// AES round with a non-trivial key.
  #[test]
  fn spot_check_rnd_key() {
    let result = round(&[0; 4], &[1, 2, 3, 4]);
    assert_eq!(
      result,
      [0x63636363 ^ 1, 0x63636363 ^ 2, 0x63636363 ^ 3, 0x63636363 ^ 4,]
    );
  }

  /// nokey variant matches round with zero key.
  #[test]
  fn spot_check_rnd_nokey() {
    let state = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10];
    assert_eq!(round_nk(&state), round(&state, &[0; 4]));
  }

  /// Active backend agrees with scalar T-table on non-trivial input.
  #[test]
  fn spot_check_impl() {
    let state = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10];
    let key = [0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    let result = round(&state, &key);
    let expected = [
      key[0]
        ^ T[0][(state[0] & 0xFF) as usize]
        ^ T[1][((state[1] >> 8) & 0xFF) as usize]
        ^ T[2][((state[2] >> 16) & 0xFF) as usize]
        ^ T[3][((state[3] >> 24) & 0xFF) as usize],
      key[1]
        ^ T[0][(state[1] & 0xFF) as usize]
        ^ T[1][((state[2] >> 8) & 0xFF) as usize]
        ^ T[2][((state[3] >> 16) & 0xFF) as usize]
        ^ T[3][((state[0] >> 24) & 0xFF) as usize],
      key[2]
        ^ T[0][(state[2] & 0xFF) as usize]
        ^ T[1][((state[3] >> 8) & 0xFF) as usize]
        ^ T[2][((state[0] >> 16) & 0xFF) as usize]
        ^ T[3][((state[1] >> 24) & 0xFF) as usize],
      key[3]
        ^ T[0][(state[3] & 0xFF) as usize]
        ^ T[1][((state[0] >> 8) & 0xFF) as usize]
        ^ T[2][((state[1] >> 16) & 0xFF) as usize]
        ^ T[3][((state[2] >> 24) & 0xFF) as usize],
    ];
    assert_eq!(result, expected);
  }

  /// CPU backend agrees with scalar.
  #[test]
  fn cpu_matches_scalar() {
    let state = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10];
    let key = [0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    assert_eq!(cpu::round(&state, &key), round(&state, &key));
    assert_eq!(cpu::round_nk(&state), round_nk(&state));
  }

  /// sub_bytes matches scalar S-box lookup.
  #[test]
  fn sub_bytes_matches_sbox() {
    let input: [u8; 16] = [
      0x00, 0x01, 0x53, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
    ];
    let result = sub_bytes(&input);
    for i in 0..16 {
      assert_eq!(result[i], SBOX[input[i] as usize], "mismatch at byte {i}");
    }
  }
}
