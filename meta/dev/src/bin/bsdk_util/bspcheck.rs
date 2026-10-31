//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Linearized chain verification.

use crate::logging;
use crate::policy;
use crate::Application;

use dash_primitives::{Block, BlockHash, BlockInvalid};
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::Checkable;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Errors that can occur during chain verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapError {
  /// A resource or configuration error during initialization.
  Config(String),
  /// An I/O error occurred while reading the input stream.
  Io(String),
  /// The input contained no frames at all.
  EmptyInput,
  /// The first frame's magic bytes do not match any known network.
  UnknownMagic { magic: [u8; 4] },
  /// A frame's magic bytes do not match the detected network.
  BadMagic {
    block: u64,
    expected: [u8; 4],
    actual: [u8; 4],
  },
  /// A frame payload exceeds the maximum allowed size.
  OversizedFrame { block: u64, size: u32, max: u32 },
  /// A block's raw bytes could not be decoded into a `Block`.
  Decode { block: u64, error: DecodeError },
  /// Re-encoding a decoded block did not reproduce the original bytes.
  WireRoundTrip { block: u64 },
  /// CBOR serialization failed.
  CborEncode { block: u64, error: String },
  /// CBOR deserialization failed.
  CborDecode { block: u64, error: String },
  /// CBOR round-trip did not reproduce the original block.
  CborRoundTrip { block: u64 },
  /// A block failed structural consistency checks.
  Check { block: u64, error: BlockInvalid },
  /// The genesis block does not match the expected hash for the network.
  GenesisAnchor { expected: BlockHash, actual: BlockHash },
  /// Aggregate error after `--no-fastfail` finishes with failures.
  Summary { errors: u64 },
}

impl fmt::Display for BootstrapError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Config(e) => write!(f, "configuration error: {e}"),
      Self::Io(e) => write!(f, "i/o error: {e}"),
      Self::EmptyInput => write!(f, "empty input"),
      Self::UnknownMagic { magic: m } => {
        write!(f, "unknown magic: 0x{:02x}{:02x}{:02x}{:02x}", m[0], m[1], m[2], m[3])
      }
      Self::BadMagic {
        block,
        expected: e,
        actual: a,
      } => {
        write!(
          f,
          "block {block}: bad magic 0x{:02x}{:02x}{:02x}{:02x} (expected 0x{:02x}{:02x}{:02x}{:02x})",
          a[0], a[1], a[2], a[3], e[0], e[1], e[2], e[3],
        )
      }
      Self::OversizedFrame { block, size, max } => {
        write!(f, "block {block}: frame size {size} exceeds maximum {max}")
      }
      Self::Decode { block, error } => write!(f, "block {block}: decode failed: {error}"),
      Self::WireRoundTrip { block } => write!(f, "block {block}: wire round-trip mismatch"),
      Self::CborEncode { block, error } => write!(f, "block {block}: cbor encode failed: {error}"),
      Self::CborDecode { block, error } => write!(f, "block {block}: cbor decode failed: {error}"),
      Self::CborRoundTrip { block } => write!(f, "block {block}: cbor round-trip mismatch"),
      Self::Check { block, error } => write!(f, "block {block}: check failed: {error}"),
      Self::GenesisAnchor { expected, actual } => {
        write!(f, "genesis anchor mismatch: expected {expected}, got {actual}")
      }
      Self::Summary { errors } => write!(f, "{errors} block(s) failed verification"),
    }
  }
}

impl std::error::Error for BootstrapError {}

impl From<io::Error> for BootstrapError {
  fn from(e: io::Error) -> Self {
    Self::Io(format!("{} ({})", e, e.kind()))
  }
}

mod magic {
  use super::BootstrapError;
  use crate::Application;

  use dash_params::{ChainParams, MessageStart, Network};

  fn detect(magic: MessageStart) -> Result<&'static ChainParams, BootstrapError> {
    Network::ALL
      .into_iter()
      .map(Network::chain)
      .find(|p| p.message_start == magic)
      .ok_or(BootstrapError::UnknownMagic { magic })
  }

  /// Identify the network from magic bytes and log the result.
  pub fn check(magic: MessageStart, app: &Application) -> Result<&'static ChainParams, BootstrapError> {
    let params = detect(magic)?;
    let [a, b, c, d] = magic;
    crate::logging::log_msg(
      app,
      &format!(
        "Magic 0x{a:02x}{b:02x}{c:02x}{d:02x} corresponds to \"{}\"",
        params.network_id
      ),
    );
    Ok(params)
  }
}

mod genesis {
  use super::BootstrapError;
  use crate::Application;

  use dash_num::Hash256;
  use dash_pow::__deps::digest::Digest;
  use dash_pow::X11;
  use dash_primitives::BlockHash;
  use dash_types::codec::DecodeError;

  /// Verify genesis block header hash matches the network.
  pub fn check(data: &[u8], expected: Hash256, app: &Application) -> Result<BlockHash, BootstrapError> {
    if data.len() < 80 {
      return Err(BootstrapError::Decode {
        block: 0,
        error: DecodeError::Eof {
          needed: 80,
          remaining: data.len(),
        },
      });
    }
    let genesis: [u8; 32] = X11::digest(&data[..80]).into();
    let genesis_hash = BlockHash::from(genesis);
    let expected_hash = BlockHash::from(expected);
    if genesis_hash != expected_hash {
      return Err(BootstrapError::GenesisAnchor {
        expected: expected_hash,
        actual: genesis_hash,
      });
    }
    crate::logging::log_msg(app, &format!("Genesis anchor: {genesis_hash}"));
    Ok(genesis_hash)
  }
}

mod diskfmt {
  use super::BootstrapError;
  use crate::policy;
  use crate::Application;

  use std::io::{self, Read};
  use std::time::{Duration, Instant};

  #[derive(Clone, Debug, Eq, Hash, PartialEq)]
  pub struct FrameHeader {
    pub magic: [u8; 4],
    pub size: u32,
  }

  /// Read an 8-byte linearized chain frame header, return `None` on clean EOF.
  pub fn read_frame_header(reader: &mut impl Read) -> Result<Option<FrameHeader>, BootstrapError> {
    let mut buf = [0u8; 8];
    // Read the first byte to distinguish clean EOF from a truncated header.
    match reader.read_exact(&mut buf[..1]) {
      Ok(()) => {}
      Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
      Err(e) => return Err(BootstrapError::Io(e.to_string())),
    }
    reader
      .read_exact(&mut buf[1..])
      .map_err(|e| BootstrapError::Io(format!("truncated frame header: {e}")))?;
    Ok(Some(FrameHeader {
      magic: [buf[0], buf[1], buf[2], buf[3]],
      size: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    }))
  }

  pub type Chunk = Vec<(u64, Vec<u8>)>;

  /// Result of a single chunk read: frames, bytes consumed, whether
  /// EOF was reached, and an optional pre-read header that did not
  /// fit in this chunk's budget.
  pub struct ChunkResult {
    pub frames: Chunk,
    pub bytes: u64,
    pub eof: bool,
    pub pending: Option<FrameHeader>,
  }

  /// Read frames into a chunk, stopping at `budget_bytes`. A
  /// `pending` header from a previous call is consumed first,
  /// avoiding stream misalignment at chunk boundaries.
  pub fn read_chunk(
    reader: &mut impl Read,
    expected_magic: [u8; 4],
    start_index: u64,
    budget_bytes: u64,
    report_secs: u64,
    app: &Application,
    pending: Option<FrameHeader>,
  ) -> Result<ChunkResult, BootstrapError> {
    let mut frames = Vec::new();
    let mut cumulative: u64 = 0;
    let mut index = start_index;
    let mut last_log_time = Instant::now();
    let mut last_log_index = start_index;
    let throttle_duration = Duration::from_secs(report_secs);
    let mut next_header = pending;

    loop {
      let header = match next_header.take() {
        Some(h) => h,
        None => match read_frame_header(reader)? {
          Some(h) => h,
          None => {
            return Ok(ChunkResult {
              frames,
              bytes: cumulative,
              eof: true,
              pending: None,
            });
          }
        },
      };

      if header.magic != expected_magic {
        return Err(BootstrapError::BadMagic {
          block: index,
          expected: expected_magic,
          actual: header.magic,
        });
      }

      if header.size > policy::MAX_FRAME_SIZE {
        return Err(BootstrapError::OversizedFrame {
          block: index,
          size: header.size,
          max: policy::MAX_FRAME_SIZE,
        });
      }

      let frame_bytes = policy::FRAME_HEADER_LEN + header.size as u64;
      if !frames.is_empty() && cumulative + frame_bytes > budget_bytes {
        return Ok(ChunkResult {
          frames,
          bytes: cumulative,
          eof: false,
          pending: Some(header),
        });
      }

      let mut data = vec![0u8; header.size as usize];
      reader.read_exact(&mut data)?;
      cumulative += frame_bytes;
      frames.push((index, data));

      let blocks_since_log = index - last_log_index;
      let time_since_log = last_log_time.elapsed();
      if blocks_since_log >= policy::REPORT_BLOCK_INTERVAL && time_since_log >= throttle_duration {
        crate::logging::log_msg(app, &format!("Read {} blocks from input", index + 1));
        last_log_time = Instant::now();
        last_log_index = index;
      }

      index += 1;
    }
  }
}

fn verify_block(index: u64, data: &[u8]) -> Result<(), BootstrapError> {
  let block = Block::decode(&mut &data[..]).map_err(|e| BootstrapError::Decode { block: index, error: e })?;

  let mut re_encoded = Vec::with_capacity(data.len());
  block.encode(&mut re_encoded);
  if re_encoded != data {
    return Err(BootstrapError::WireRoundTrip { block: index });
  }

  let mut cbor_bytes = Vec::new();
  ciborium::into_writer(&block, &mut cbor_bytes).map_err(|e| BootstrapError::CborEncode {
    block: index,
    error: e.to_string(),
  })?;
  let decoded_from_cbor: Block =
    ciborium::from_reader(&cbor_bytes[..]).map_err(|e: ciborium::de::Error<io::Error>| BootstrapError::CborDecode {
      block: index,
      error: e.to_string(),
    })?;
  if decoded_from_cbor != block {
    return Err(BootstrapError::CborRoundTrip { block: index });
  }

  if let Some(e) = block.check() {
    return Err(BootstrapError::Check { block: index, error: e });
  }

  Ok(())
}

pub fn run(
  app: &Application,
  file: &str,
  threads: usize,
  memory_mib: u64,
  report_freq: u64,
  no_fastfail: bool,
  progress: bool,
) -> Result<(), BootstrapError> {
  let start = Instant::now();
  let from_stdin = file == "-";

  let max_threads = crate::platform::system_threads();
  let effective_threads = if threads == 0 {
    policy::default_threads()
  } else {
    threads.clamp(1, max_threads)
  };
  let pool = rayon::ThreadPoolBuilder::new()
    .num_threads(effective_threads)
    .build()
    .map_err(|e| BootstrapError::Config(format!("failed to create thread pool: {e}")))?;
  let thread_count = pool.current_num_threads();

  let budget_mib = if memory_mib == 0 {
    policy::default_memory_mib()
  } else {
    memory_mib
  };
  let budget_bytes = budget_mib.saturating_mul(1024 * 1024);

  logging::log_msg(
    app,
    &format!("Threads: {thread_count}, memory budget: {budget_mib} MiB, report every {report_freq}s"),
  );

  let (input, file_size): (Box<dyn Read>, Option<u64>) = if from_stdin {
    logging::log_msg(app, "Reading from stdin (streaming)");
    (Box::new(io::stdin().lock()), None)
  } else {
    let full_path = fs::canonicalize(file).unwrap_or_else(|_| file.into());
    let metadata = fs::metadata(file)?;
    let size_mib = metadata.len() / (1024 * 1024);
    logging::log_msg(app, &format!("Reading {} ({size_mib} MiB)", full_path.display()));
    (Box::new(File::open(file)?), Some(metadata.len()))
  };

  let mut reader = BufReader::with_capacity(policy::READ_BUFFER_BYTES, input);

  let first_header = diskfmt::read_frame_header(&mut reader)?.ok_or(BootstrapError::EmptyInput)?;

  let params = magic::check(first_header.magic, app)?;

  if first_header.size > policy::MAX_FRAME_SIZE {
    return Err(BootstrapError::OversizedFrame {
      block: 0,
      size: first_header.size,
      max: policy::MAX_FRAME_SIZE,
    });
  }

  let mut genesis_data = vec![0u8; first_header.size as usize];
  reader.read_exact(&mut genesis_data)?;
  let genesis_bytes = policy::FRAME_HEADER_LEN + first_header.size as u64;

  genesis::check(&genesis_data, params.consensus.hash_genesis_block, app)?;

  if progress {
    let bar = match file_size {
      Some(total) => {
        let b = ProgressBar::new(total);
        b.set_style(
          ProgressStyle::default_bar()
            .template("{bar:40} {bytes}/{total_bytes} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        b
      }
      None => {
        let b = ProgressBar::new_spinner();
        b.set_style(
          ProgressStyle::default_spinner()
            .template("{spinner} {bytes} ({elapsed})")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        b
      }
    };
    bar.inc(genesis_bytes);
    app.pb.set(bar).ok();
  }

  logging::log_msg(app, &format!("Dispatching verification across {thread_count} threads"));

  verify_chunks(
    app,
    &pool,
    &mut reader,
    params,
    genesis_data,
    budget_bytes,
    report_freq,
    no_fastfail,
    start,
  )
}

fn verify_chunks(
  app: &Application,
  pool: &rayon::ThreadPool,
  reader: &mut BufReader<Box<dyn Read>>,
  params: &dash_params::ChainParams,
  genesis_data: Vec<u8>,
  budget_bytes: u64,
  report_secs: u64,
  no_fastfail: bool,
  start: Instant,
) -> Result<(), BootstrapError> {
  let interrupted = AtomicBool::new(false);
  let first_error: Mutex<Option<BootstrapError>> = Mutex::new(None);
  let error_count = AtomicU64::new(0);
  let ok_count = AtomicU64::new(0);

  match verify_block(0, &genesis_data) {
    Ok(()) => {
      ok_count.fetch_add(1, Ordering::Relaxed);
    }
    Err(e) => {
      logging::log_msg(app, &format!("Error: {e}"));
      error_count.fetch_add(1, Ordering::Relaxed);
      if !no_fastfail {
        return Err(e);
      }
    }
  }

  drop(genesis_data);

  let mut block_index: u64 = 1;
  let mut chunk_num: u64 = 0;
  let mut pending_header: Option<diskfmt::FrameHeader> = None;

  loop {
    if !no_fastfail && interrupted.load(Ordering::Acquire) {
      break;
    }

    let cr = match diskfmt::read_chunk(
      reader,
      params.message_start,
      block_index,
      budget_bytes,
      report_secs,
      app,
      pending_header.take(),
    ) {
      Ok(v) => v,
      Err(e) => {
        if let Some(bar) = app.pb.get() {
          bar.finish_and_clear();
        }
        return Err(e);
      }
    };

    if cr.frames.is_empty() {
      break;
    }

    let chunk_len = cr.frames.len() as u64;
    let reached_eof = cr.eof;
    pending_header = cr.pending;

    pool.install(|| {
      cr.frames.par_iter().for_each(|(idx, data)| {
        if !no_fastfail && interrupted.load(Ordering::Acquire) {
          return;
        }

        match verify_block(*idx, data) {
          Ok(()) => {
            ok_count.fetch_add(1, Ordering::Relaxed);
          }
          Err(e) => {
            logging::log_msg(app, &format!("Error: {e}"));
            error_count.fetch_add(1, Ordering::Relaxed);
            if !no_fastfail {
              interrupted.store(true, Ordering::Release);
              logging::log_msg(app, "Interrupting remaining blocks");
              let mut guard = first_error.lock().unwrap_or_else(|p| p.into_inner());
              if guard.is_none() {
                *guard = Some(e);
              }
            }
          }
        }
      });
    });

    if let Some(bar) = app.pb.get() {
      bar.inc(cr.bytes);
    }

    logging::log_msg(
      app,
      &format!(
        "Chunk {chunk_num}: verified {chunk_len} blocks ({ok} ok)",
        ok = ok_count.load(Ordering::Relaxed)
      ),
    );

    block_index += chunk_len;
    chunk_num += 1;

    if reached_eof || (!no_fastfail && interrupted.load(Ordering::Acquire)) {
      break;
    }
  }

  if let Some(bar) = app.pb.get() {
    bar.finish_and_clear();
  }

  let ok = ok_count.load(Ordering::Relaxed);
  let errs = error_count.load(Ordering::Relaxed);
  let verified = ok + errs;
  let abandoned = block_index.saturating_sub(verified);

  let runtime = logging::format_runtime(start.elapsed());
  logging::log_msg(app, &format!("Verified: {ok}/{verified} blocks in {runtime}"));
  if abandoned > 0 {
    logging::log_msg(app, &format!("Abandoned: {abandoned} blocks (interrupted)"));
  }

  if errs > 0 {
    if no_fastfail {
      return Err(BootstrapError::Summary { errors: errs });
    }
    if let Some(e) = first_error.lock().unwrap_or_else(|p| p.into_inner()).take() {
      return Err(e);
    }
    return Err(BootstrapError::Summary { errors: errs });
  }

  logging::log_msg(app, "All blocks passed verification");
  Ok(())
}
