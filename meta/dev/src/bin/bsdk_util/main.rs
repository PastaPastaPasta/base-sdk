//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Entrypoint for Base SDK Debug Utility.

mod bspcheck;
mod logging;
mod platform;
mod policy;

use clap::{Parser, Subcommand};
use indicatif::ProgressBar;

use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};

/// Application shared state.
pub struct Application {
  /// Progress bar, set at most once after file size is known.
  pub pb: OnceLock<ProgressBar>,
  /// Optional log-file writer.
  pub log: Mutex<Option<BufWriter<File>>>,
  /// Path to the log file on disk.
  pub log_path: String,
}

impl fmt::Debug for Application {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Application")
      .field("pb", &self.pb.get().is_some())
      .field("log_path", &self.log_path)
      .finish_non_exhaustive()
  }
}

impl Application {
  fn new(log_path: Option<String>) -> Self {
    let log_path = log_path.unwrap_or_default();
    let log = if log_path.is_empty() {
      Mutex::new(None)
    } else {
      match OpenOptions::new().write(true).create_new(true).open(&log_path) {
        Ok(f) => Mutex::new(Some(BufWriter::new(f))),
        Err(e) => {
          eprintln!("warning: could not create log file: {e}");
          Mutex::new(None)
        }
      }
    };
    Self {
      pb: OnceLock::new(),
      log,
      log_path,
    }
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Parser)]
#[command(name = "bsdk-util", about = "Base SDK Debug Utility")]
struct Cli {
  /// Write a log file to this path.
  #[arg(long, global = true)]
  log: Option<String>,

  #[command(subcommand)]
  command: Command,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Subcommand)]
enum Command {
  /// Verify every block in a linearized chain.
  Bspcheck {
    /// Number of verification threads (0 = auto).
    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,

    /// Max memory for block data in MiB (0 = auto).
    #[arg(short = 'm', long, default_value_t = 0)]
    memory: u64,

    /// Minimum seconds between progress reports.
    #[arg(short = 'r', long, default_value_t = 5)]
    report_freq: u64,

    /// Continue processing after errors instead of aborting.
    #[arg(short = 'n', long)]
    no_fastfail: bool,

    /// Show a progress bar.
    #[arg(short = 'p', long)]
    progress: bool,

    /// Path to a linearized chain, or "-" for stdin.
    file: String,
  },
}

fn main() -> ExitCode {
  let cli = Cli::parse();
  let app = Application::new(cli.log);

  logging::print_banner(&app);

  let args: Vec<String> = env::args().skip(1).collect();
  let joined_args = args.join(" ");
  logging::log_msg(
    &app,
    &format!(
      "Running on {} {} ({}) with args \"{joined_args}\"",
      env::consts::OS,
      env::consts::FAMILY,
      env::consts::ARCH,
    ),
  );

  let result = match cli.command {
    Command::Bspcheck {
      threads,
      memory,
      report_freq,
      no_fastfail,
      progress,
      file,
    } => bspcheck::run(&app, &file, threads, memory, report_freq, no_fastfail, progress),
  };

  match result {
    Ok(()) => {
      if let Some(mut w) = app.log.lock().ok().and_then(|mut g| g.take()) {
        if let Err(e) = w.flush() {
          eprintln!("fatal: log flush failed: {e}");
          return ExitCode::FAILURE;
        }
        logging::log_msg(&app, &format!("Log saved to {}", app.log_path));
      }
      ExitCode::SUCCESS
    }
    Err(e) => {
      logging::log_msg(&app, &format!("Fatal: {e}"));
      eprintln!("fatal: {e}");
      ExitCode::FAILURE
    }
  }
}
