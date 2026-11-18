//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Logging, formatting and text manipulation.

use crate::Application;

use built_info::{DIRECT_DEPENDENCIES, GIT_COMMIT_HASH_SHORT, PKG_VERSION, RUSTC_VERSION};

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod built_info {
  include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Write a timestamped message to stderr and optionally to a log file.
pub fn log_msg(app: &Application, msg: &str) {
  let ts = utc_timestamp(SystemTime::now());
  let line = format!("[{ts}] {msg}");

  match app.pb.get() {
    Some(bar) => bar.println(&line),
    None => eprintln!("{line}"),
  }

  if let Ok(mut guard) = app.log.lock() {
    if let Some(ref mut w) = *guard {
      if writeln!(w, "{line}").is_err() {
        *guard = None;
        eprintln!("warning: log file write failed, logging disabled");
      }
    }
  }
}

/// Print a startup banner with version and build metadata.
pub fn print_banner(app: &Application) {
  eprintln!();
  eprintln!();

  let git_hash = GIT_COMMIT_HASH_SHORT.unwrap_or("unknown");

  log_msg(app, &format!("Base SDK Debug Utility v{PKG_VERSION} ({git_hash})"));
  log_msg(app, "Copyright (c) 2026, The Dash Core developers");
  log_msg(app, "");
  log_msg(app, "Build Info:");
  log_msg(app, &format!("  {RUSTC_VERSION}"));
  for &(name, version) in DIRECT_DEPENDENCIES.iter() {
    if name.starts_with("dash-") {
      log_msg(app, &format!("  {name} v{version}"));
    }
  }
  log_msg(app, "");
}

/// Format `time` as `YYYY-MM-DDTHH:MM:SSZ` in UTC.
fn utc_timestamp(time: SystemTime) -> String {
  let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
  let (days, rem) = (secs / 86_400, secs % 86_400);
  // Days since 1970-01-01 to a proleptic Gregorian date, in 400-year eras
  // starting on 0000-03-01.
  let z = days + 719_468;
  let (era, doe) = (z / 146_097, z % 146_097);
  let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let day = doy - (153 * mp + 2) / 5 + 1;
  let month = if mp < 10 { mp + 3 } else { mp - 9 };
  let year = era * 400 + yoe + u64::from(month <= 2);
  let (hour, minute, second) = (rem / 3_600, rem / 60 % 60, rem % 60);
  format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Format a duration as a compact human-readable string.
pub fn format_runtime(elapsed: Duration) -> String {
  let secs = elapsed.as_secs();
  let days = secs / 86_400;
  let hours = secs / 3_600 % 24;
  let minutes = secs / 60 % 60;
  let seconds = secs % 60;
  let mut parts = Vec::new();
  if days > 0 {
    parts.push(format!("{days}d"));
  }
  if hours > 0 {
    parts.push(format!("{hours}h"));
  }
  if minutes > 0 {
    parts.push(format!("{minutes}m"));
  }
  if parts.is_empty() {
    let millis = elapsed.subsec_millis();
    parts.push(format!("{seconds}.{millis:03}s"));
  } else {
    parts.push(format!("{seconds}s"));
  }
  parts.join(" ")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn utc_timestamp_crosses_leap_days_and_centuries() {
    for (secs, expected) in [
      (0, "1970-01-01T00:00:00Z"),
      (951_782_399, "2000-02-28T23:59:59Z"),
      (951_782_400, "2000-02-29T00:00:00Z"),
      (4_107_542_400, "2100-03-01T00:00:00Z"),
    ] {
      assert_eq!(utc_timestamp(UNIX_EPOCH + Duration::from_secs(secs)), expected);
    }
  }
}
