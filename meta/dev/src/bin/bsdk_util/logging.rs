//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Logging, formatting and text manipulation.

use crate::Application;

use built_info::{DIRECT_DEPENDENCIES, GIT_COMMIT_HASH_SHORT, PKG_VERSION, RUSTC_VERSION};
use chrono::{TimeDelta, Utc};

use std::io::Write;

mod built_info {
  include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Write a timestamped message to stderr and optionally to a log file.
pub fn log_msg(app: &Application, msg: &str) {
  let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
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

/// Format a duration as a compact human-readable string.
pub fn format_runtime(elapsed: std::time::Duration) -> String {
  let delta = TimeDelta::from_std(elapsed).unwrap_or(TimeDelta::zero());
  let days = delta.num_days();
  let hours = delta.num_hours() % 24;
  let minutes = delta.num_minutes() % 60;
  let seconds = delta.num_seconds() % 60;
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
    let millis = delta.num_milliseconds() % 1000;
    parts.push(format!("{seconds}.{millis:03}s"));
  } else {
    parts.push(format!("{seconds}s"));
  }
  parts.join(" ")
}
