//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core's string to integer conversions for chain-params options.

/// Reads `std::from_chars` digits for a signed type at the start of `s`.
///
/// Returns the value (`None` on overflow of `i64`) and the bytes read, or
/// `None` when `s` holds no digits after an optional `-`.
fn from_chars(s: &[u8]) -> Option<(Option<i64>, usize)> {
  let negative = s.first() == Some(&b'-');
  let start = usize::from(negative);
  let digits = s[start..].iter().take_while(|c| c.is_ascii_digit()).count();
  if digits == 0 {
    return None;
  }
  let value = s[start..start + digits].iter().try_fold(0_i64, |v, &c| {
    let (v, digit) = (v.checked_mul(10)?, i64::from(c - b'0'));
    if negative {
      v.checked_sub(digit)
    } else {
      v.checked_add(digit)
    }
  });
  Some((value, start + digits))
}

/// Drops one leading `+`, as `strtol` does; `None` for `+-`.
fn strip_plus(b: &[u8]) -> Option<&[u8]> {
  if b.starts_with(b"+-") {
    return None;
  }
  Some(b.strip_prefix(b"+").unwrap_or(b))
}

/// Core's `ParseInt64` (`ParseIntegral`): one optional leading `+` (not `+-`),
/// then the whole rest must be `from_chars` digits within range.
pub(crate) fn parse_i64(s: &str) -> Option<i64> {
  let b = strip_plus(s.as_bytes())?;
  match from_chars(b) {
    Some((value, read)) if read == b.len() => value,
    _ => None,
  }
}

/// Core's `ParseInt32`: [`parse_i64`] restricted to `int32_t`.
pub(crate) fn parse_i32(s: &str) -> Option<i32> {
  parse_i64(s).and_then(|v| i32::try_from(v).ok())
}

/// Core's `LocaleIndependentAtoi<int64_t>`, behind `GetIntArg`.
///
/// Trims ASCII whitespace, accepts one `+` (`+-` is 0), parses the leading
/// digits, ignores the rest, and saturates on overflow. No digits give 0.
pub(crate) fn atoi_i64(s: &str) -> i64 {
  let s = s.trim_matches(|c| matches!(c, ' ' | '\x0c' | '\n' | '\r' | '\t' | '\x0b'));
  let Some(b) = strip_plus(s.as_bytes()) else {
    return 0;
  };
  match from_chars(b) {
    Some((Some(v), _)) => v,
    Some((None, _)) if b.first() == Some(&b'-') => i64::MIN,
    Some((None, _)) => i64::MAX,
    None => 0,
  }
}

/// Core's `GetIntArg` stored into an `int`: [`atoi_i64`], then the
/// implementation-defined (modular) conversion to `int`.
#[expect(clippy::cast_possible_truncation, reason = "Core's int64_t to int conversion")]
pub(crate) fn int_arg(s: &str) -> i32 {
  atoi_i64(s) as i32
}

/// Core's `InterpretBool`, behind `GetBoolArg` for a string setting.
///
/// Empty is true; otherwise `LocaleIndependentAtoi<int>` is compared to 0.
/// Saturating to `int` keeps the sign, so the `int64_t` value decides alike.
pub(crate) fn interpret_bool(s: &str) -> bool {
  s.is_empty() || atoi_i64(s) != 0
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  #[rstest]
  #[case("0", Some(0))]
  #[case("-0", Some(0))]
  #[case("+7", Some(7))]
  #[case("007", Some(7))]
  #[case("9223372036854775807", Some(i64::MAX))]
  #[case("-9223372036854775808", Some(i64::MIN))]
  #[case("9223372036854775808", None)]
  #[case("", None)]
  #[case("+", None)]
  #[case("-", None)]
  #[case("+-1", None)]
  #[case("++1", None)]
  #[case("-+1", None)]
  #[case(" 1", None)]
  #[case("1 ", None)]
  #[case("1x", None)]
  #[case("0x7", None)]
  #[case("2.5", None)]
  fn parse_i64_as_core(#[case] s: &str, #[case] want: Option<i64>) {
    assert_eq!(parse_i64(s), want);
  }

  #[rstest]
  #[case("2147483647", Some(i32::MAX))]
  #[case("2147483648", None)]
  #[case("-2147483648", Some(i32::MIN))]
  #[case("-2147483649", None)]
  fn parse_i32_range(#[case] s: &str, #[case] want: Option<i32>) {
    assert_eq!(parse_i32(s), want);
  }

  #[rstest]
  #[case(" 12abc", 12)]
  #[case("\t-5\n", -5)]
  #[case("+-5", 0)]
  #[case("+5", 5)]
  #[case("abc", 0)]
  #[case("", 0)]
  #[case("99999999999999999999", i64::MAX)]
  #[case("-99999999999999999999", i64::MIN)]
  fn atoi_as_core(#[case] s: &str, #[case] want: i64) {
    assert_eq!(atoi_i64(s), want);
  }

  #[rstest]
  #[case("4294967297", 1)]
  #[case("99999999999", 1_215_752_191)]
  #[case("2147483648", i32::MIN)]
  #[case("-1", -1)]
  fn int_arg_wraps(#[case] s: &str, #[case] want: i32) {
    assert_eq!(int_arg(s), want);
  }

  #[rstest]
  #[case("", true)]
  #[case("0", false)]
  #[case("1", true)]
  #[case(" 2x", true)]
  #[case("x", false)]
  #[case("4294967296", true)]
  fn interpret_bool_as_core(#[case] s: &str, #[case] want: bool) {
    assert_eq!(interpret_bool(s), want);
  }
}
