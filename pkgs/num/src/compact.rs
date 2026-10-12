//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compact difficulty target encoding.

use crate::Arith256;

use dash_types::__private::__read_hex as read_hex;
use dash_types::impl_num;
use dash_types::{Numeric, ParseHexError};

use core::fmt;
use core::str::FromStr;

/// Compact difficulty target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompactTarget(u32);

/// Result of decoding a compact difficulty target.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DecodedTarget {
  /// The decoded 256-bit target value.
  pub value: Arith256,
  /// Whether the sign bit was set in the mantissa.
  pub negative: bool,
  /// Whether the encoded exponent exceeds the valid range.
  pub overflow: bool,
}

impl Numeric for CompactTarget {
  type Base = u32;

  type Bytes = [u8; 4];

  const ZERO: Self = Self(0);

  fn from_base(v: u32) -> Self {
    Self(v)
  }

  fn to_base(&self) -> u32 {
    self.0
  }

  fn from_lendian(bytes: [u8; 4]) -> Self {
    Self::from_base(u32::from_lendian(bytes))
  }

  fn to_lendian(&self) -> [u8; 4] {
    self.0.to_lendian()
  }

  fn from_bendian(bytes: [u8; 4]) -> Self {
    Self::from_base(u32::from_bendian(bytes))
  }

  fn to_bendian(&self) -> [u8; 4] {
    self.0.to_bendian()
  }
}

impl_num!(CompactTarget, u32);

impl CompactTarget {
  /// Wraps a raw `nBits` word.
  #[inline]
  pub fn new(bits: u32) -> Self {
    Self(bits)
  }

  /// Expand this compact (nBits) representation to a 256-bit target value.
  pub fn expand(self) -> DecodedTarget {
    let compact = self.0;
    let size = (compact >> 24) as usize;
    let mut word = compact & 0x007f_ffff;

    let value = if size <= 3 {
      word >>= 8 * (3 - size);
      Arith256::from_u64(word as u64)
    } else {
      let v = Arith256::from_u64(word as u64);
      v.wrapping_shl((8 * (size - 3)) as u32)
    };

    let negative = word != 0 && (compact & 0x0080_0000) != 0;
    let overflow = word != 0 && ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32));

    DecodedTarget {
      value,
      negative,
      overflow,
    }
  }

  /// Work contributed by a block with this target.
  ///
  /// Zero when the target is negative, overflows or is zero.
  pub fn block_proof(self) -> Arith256 {
    let target = self.expand();
    if target.negative || target.overflow || target.value == Arith256::ZERO {
      return Arith256::ZERO;
    }
    target.value.block_proof()
  }
}

impl fmt::Display for CompactTarget {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:#010x}", self.0)
  }
}

/// Parses the hex rendered by [`Display`](fmt::Display).
impl FromStr for CompactTarget {
  type Err = ParseHexError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    read_hex::<4>(digits, false).map(Self::from_bendian)
  }
}

impl Arith256 {
  /// Compact this value to its `nBits` representation.
  pub fn compact(self, negative: bool) -> CompactTarget {
    let mut size = self.bits().div_ceil(8);
    let mut compact: u32 = if size <= 3 {
      (self.low_u64() << (8 * (3 - size as u64))) as u32
    } else {
      let bn = self.wrapping_shr(8 * (size - 3));
      bn.low_u64() as u32
    };

    // Bit 23 denotes the sign. When already set, shift the mantissa right
    // and bump the exponent.
    if compact & 0x0080_0000 != 0 {
      compact >>= 8;
      size += 1;
    }

    compact &= 0x007f_ffff;
    compact |= size << 24;
    if negative && (compact & 0x007f_ffff) != 0 {
      compact |= 0x0080_0000;
    }

    CompactTarget(compact)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::prelude::*;
  use crate::{Arith256, CompactTarget};

  use dash_dev::Corpus;
  use dash_types::Numeric;
  use rstest::*;
  use serde::Deserialize;

  use core::str::FromStr;

  /// Assert compact decode flags match expectations.
  fn check_compact(compact: u32, expected_negative: bool, expected_overflow: bool) {
    let ct = CompactTarget::new(compact).expand();
    assert_eq!(
      ct.negative, expected_negative,
      "negative mismatch for compact {compact:#010x}"
    );
    assert_eq!(
      ct.overflow, expected_overflow,
      "overflow mismatch for compact {compact:#010x}"
    );
  }

  /// Zero-valued compacts that decode to zero, not negative, not overflow.
  #[rstest]
  #[case(0x0000_0000)]
  #[case(0x0012_3456)]
  #[case(0x0100_3456)]
  #[case(0x0200_0056)]
  #[case(0x0300_0000)]
  #[case(0x0400_0000)]
  fn zero_value(#[case] compact: u32) {
    let ct = CompactTarget::new(compact).expand();
    assert_eq!(ct.value, Arith256::ZERO);
    assert_eq!(ct.value.compact(false), CompactTarget::new(0));
    check_compact(compact, false, false);
  }

  /// Sign bit set but word becomes zero after shift, so negative stays false.
  #[rstest]
  #[case(0x0092_3456)]
  #[case(0x0180_3456)]
  #[case(0x0280_0056)]
  #[case(0x0380_0000)]
  #[case(0x0480_0000)]
  fn sign_bit_but_zero_word(#[case] compact: u32) {
    let ct = CompactTarget::new(compact).expand();
    assert_eq!(ct.value, Arith256::ZERO);
    assert_eq!(ct.value.compact(false), CompactTarget::new(0));
    check_compact(compact, false, false);
  }

  #[rstest]
  fn compact_01123456() {
    let ct = CompactTarget::new(0x01123456).expand();
    assert_eq!(ct.value, Arith256::from_u64(0x12));
    assert_eq!(ct.value.compact(false), CompactTarget::new(0x01120000));
    check_compact(0x01123456, false, false);
  }

  #[rstest]
  fn compact_0x80_avoids_sign_bit() {
    let num = Arith256::from_u64(0x80);
    assert_eq!(num.compact(false), CompactTarget::new(0x02008000));
  }

  #[rstest]
  fn compact_01fedcba() {
    // word=0x7edcba, size=1, shifted=0x7e, sign bit set
    let ct = CompactTarget::new(0x01fedcba).expand();
    assert_eq!(ct.value, Arith256::from_u64(0x7e));
    assert!(ct.negative);
    assert!(!ct.overflow);
    assert_eq!(ct.value.compact(true), CompactTarget::new(0x01fe0000));
  }

  /// Non-zero values with expected compact roundtrips.
  #[rstest]
  #[case(0x0212_3456, 0x1234, 0x0212_3400)]
  #[case(0x0312_3456, 0x12_3456, 0x0312_3456)]
  #[case(0x0412_3456, 0x1234_5600, 0x0412_3456)]
  fn positive_values(#[case] compact: u32, #[case] expected_val: u64, #[case] expected_roundtrip: u32) {
    let ct = CompactTarget::new(compact).expand();
    assert_eq!(ct.value, Arith256::from_u64(expected_val));
    assert_eq!(ct.value.compact(false), CompactTarget::new(expected_roundtrip));
    check_compact(compact, false, false);
  }

  #[rstest]
  fn compact_04923456_negative() {
    let ct = CompactTarget::new(0x04923456).expand();
    assert_eq!(ct.value, Arith256::from_u64(0x12345600));
    assert!(ct.negative);
    assert!(!ct.overflow);
    assert_eq!(ct.value.compact(true), CompactTarget::new(0x04923456));
  }

  #[rstest]
  fn compact_05009234() {
    let ct = CompactTarget::new(0x05009234).expand();
    assert_eq!(ct.value, Arith256::from_u64(0x92340000));
    assert_eq!(ct.value.compact(false), CompactTarget::new(0x05009234));
    check_compact(0x05009234, false, false);
  }

  #[rstest]
  fn compact_20123456() {
    let ct = CompactTarget::new(0x20123456).expand();
    assert_eq!(ct.value.compact(false), CompactTarget::new(0x20123456));
    check_compact(0x20123456, false, false);
  }

  #[rstest]
  fn compact_ff123456_overflow() {
    let ct = CompactTarget::new(0xff123456).expand();
    assert!(!ct.negative);
    assert!(ct.overflow);
  }

  #[rstest]
  #[case(0x0100_3456_u32, 0x00_u64)]
  #[case(0x0112_3456_u32, 0x12_u64)]
  #[case(0x0200_8000_u32, 0x80_u64)]
  #[case(0x0500_9234_u32, 0x9234_0000_u64)]
  #[case(0x0492_3456_u32, 0x00_u64)]
  #[case(0x0412_3456_u32, 0x1234_5600_u64)]
  fn target_from_compact_ported(#[case] n_bits: u32, #[case] target: u64) {
    let decoded = CompactTarget::new(n_bits).expand();
    // For negative-flagged values the target is 0.
    if decoded.negative {
      assert_eq!(Arith256::from_u64(target), Arith256::ZERO);
    } else {
      assert_eq!(decoded.value, Arith256::from_u64(target));
    }
  }

  /// CompactTarget display.
  #[rstest]
  fn display() {
    assert_eq!(format!("{}", CompactTarget::new(0x1d00ffff)), "0x1d00ffff");
  }

  #[rstest]
  #[case("0x1d00ffff", 0x1d00_ffff)]
  #[case("1d00ffff", 0x1d00_ffff)]
  #[case("0X1D00FFFF", 0x1d00_ffff)]
  #[case("00000001", 1)]
  fn from_str_accepts(#[case] text: &str, #[case] want: u32) {
    let parsed = CompactTarget::from_str(text).unwrap();
    assert_eq!(parsed, CompactTarget::new(want));
  }

  #[rstest]
  #[case("")]
  #[case("0x")]
  #[case("1")]
  #[case("1d00fff")]
  #[case("1d00ffff0")]
  #[case("1d00fffg")]
  #[case(" 1d00ffff")]
  fn from_str_rejects(#[case] text: &str) {
    assert!(CompactTarget::from_str(text).is_err());
  }

  #[rstest]
  fn display_round_trips() {
    let ct = CompactTarget::new(0x1d00_ffff);
    assert_eq!(CompactTarget::from_str(&format!("{ct}")).unwrap(), ct);
  }

  #[derive(Deserialize)]
  struct BlockProofVector {
    nbits: String,
    r: String,
  }

  #[test]
  fn block_proof_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "arith256");
    let vecs: Vec<BlockProofVector> = corpus.vectors("block_proof");

    for v in &vecs {
      let nbits = u32::from_str_radix(&v.nbits, 16).unwrap();
      let want = Arith256::from_str(&v.r).unwrap();
      assert_eq!(
        CompactTarget::new(nbits).block_proof(),
        want,
        "block_proof({})",
        v.nbits
      );
    }
  }

  #[rstest]
  #[case(0x0300_0001, Arith256::ONE << 255u32)]
  #[case(0x1d00_ffff, Arith256::from_u64(0x1_0001_0001))]
  #[case(0x207f_ffff, Arith256::from_u64(2))]
  #[case(0x2100_ffff, Arith256::ONE)]
  fn block_proof_valid_target(#[case] nbits: u32, #[case] want: Arith256) {
    assert_eq!(CompactTarget::new(nbits).block_proof(), want);
  }
}
