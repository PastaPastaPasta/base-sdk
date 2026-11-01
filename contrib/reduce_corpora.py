#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Reduce AFL++ queues into a committed fuzz corpus.

Pools the queue of every instance under each AFL++ output directory with the
corpus and runs `afl-cmin.bash` once per binary to keep one input per coverage
tuple. The corpus becomes the union of survivors, named by their SHA-1. The
Python `afl-cmin` writes nothing on macOS and the awk one refuses to run.

Usage:

  ./contrib/reduce_corpora.py \\
    --output /Volumes/mrd-fuzz/out/blake \\
    --binary /Volumes/mrd-fuzz/target/release/blake \\
    --corpus fuzz/pow/corpora/blake
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import RETCODE_ERR, RETCODE_PASS

# Where `cargo afl` builds AFL++, one directory per toolchain and version.
AFL_HOME = Path.home() / ".local" / "share" / "afl.rs"
# Each AFL++ process holds a System V shared memory segment, and macOS allows
# only 32 across the system, so a few running fuzzers leave little headroom.
DEFAULT_JOBS = 4


def _afl_bin(given: Path | None) -> Path:
  """Return the AFL++ tool directory, *given* or the newest `cargo afl` one."""
  if given is not None:
    candidates = [given]
  elif "AFL_PATH" in os.environ:
    candidates = [Path(os.environ["AFL_PATH"])]
  else:
    candidates = sorted(
      AFL_HOME.glob("*/*/afl/bin"),
      key=lambda path: path.stat().st_mtime,
      reverse=True,
    )
  for candidate in candidates:
    if (candidate / "afl-cmin.bash").is_file():
      return candidate
  raise FileNotFoundError("no AFL++ build found, run `just fuzz::setup` first")


def _run(afl_bin: Path, *args: str | Path) -> None:
  """Run an AFL++ tool from *afl_bin*, raising with its output on failure."""
  # A persistent loop runs its one-time setup on the first input only, so
  # `afl-tmin` would see every later input as a new path.
  env = {
    **os.environ,
    "AFL_FUZZER_LOOPCOUNT": "1",
    "AFL_PATH": str(afl_bin),
    "AFL_SKIP_CPUFREQ": "1",
    "PATH": f"{afl_bin}{os.pathsep}{os.environ.get('PATH', '')}",
  }
  proc = subprocess.run(  # noqa: S603
    [str(arg) for arg in args],
    capture_output=True,
    check=False,
    env=env,
    text=True,
  )
  if proc.returncode != 0:
    detail = proc.stderr.strip() or proc.stdout.strip()
    raise RuntimeError(f"{Path(args[0]).name} failed: {detail}")


def _sizes(paths: list[Path]) -> str:
  """Return the count and total size of *paths*."""
  total = sum(path.stat().st_size for path in paths)
  return f"{len(paths)} files, {total} bytes"


def _digest(data: bytes) -> str:
  """Return the SHA-1 name of *data*."""
  return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def _reduce(args: argparse.Namespace) -> int:
  afl_bin = _afl_bin(args.afl_bin)
  # `afl-fuzz -M` and `-S` name each instance's directory; other runs use
  # `default`.
  queues = sorted(
    queue
    for output in args.output
    for queue in output.glob("*/queue")
    if queue.is_dir()
  )
  if not queues:
    raise RuntimeError("none of the outputs hold a queue")
  inputs = [
    path for queue in queues for path in queue.iterdir() if path.is_file()
  ]
  print(f"queue: {_sizes(inputs)}")
  # The corpus joins the pool so no committed input is dropped unexamined.
  if args.corpus.is_dir():
    inputs += [path for path in args.corpus.iterdir() if path.is_file()]

  with tempfile.TemporaryDirectory(dir=queues[0].parent) as work:
    pool = Path(work) / "pool"
    pool.mkdir()
    for path in inputs:
      data = path.read_bytes()
      (pool / _digest(data)).write_bytes(data)

    # Each binary keeps the inputs its own coverage needs. An input kept by
    # one binary is trimmed with it; one kept by several stays whole, since
    # trimming for one binary may lose coverage of another.
    keepers: dict[str, list[Path]] = {}
    for index, binary in enumerate(args.binary):
      kept = Path(work) / f"cmin{index}"
      cmin = afl_bin / "afl-cmin.bash"
      _run(afl_bin, cmin, "-i", pool, "-o", kept, "--", binary)
      # `AFL_KEEP_TRACES` leaves a `.traces` directory beside the survivors.
      survivors = sorted(path for path in kept.iterdir() if path.is_file())
      # A silent failure leaves no inputs, which is never a valid reduction.
      if not survivors:
        raise RuntimeError(f"afl-cmin kept no inputs for {binary}")
      print(f"cmin:  {_sizes(survivors)} for {binary}")
      for path in survivors:
        keepers.setdefault(path.name, []).append(binary)

    trimmed = Path(work) / "tmin"
    trimmed.mkdir()
    tmin = afl_bin / "afl-tmin"
    with ThreadPoolExecutor(max_workers=args.jobs) as pool_jobs:
      jobs = []
      for name, binaries in keepers.items():
        if len(binaries) == 1:
          command = (tmin, "-i", pool / name, "-o", trimmed / name)
          jobs.append(
            pool_jobs.submit(_run, afl_bin, *command, "--", binaries[0])
          )
        else:
          shutil.copyfile(pool / name, trimmed / name)
      for job in jobs:
        job.result()

    # Inputs that trim to the same bytes share a name and collapse into one.
    reduced = {}
    for path in trimmed.iterdir():
      data = path.read_bytes()
      reduced[_digest(data)] = data
    print(f"tmin:  {_sizes(list(trimmed.iterdir()))}, {len(reduced)} distinct")

  args.corpus.mkdir(parents=True, exist_ok=True)
  for stale in args.corpus.iterdir():
    if stale.is_file():
      stale.unlink()
  for name, data in reduced.items():
    (args.corpus / name).write_bytes(data)
  print(f"wrote {args.corpus}")
  return RETCODE_PASS


def _parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
  )
  parser.add_argument(
    "--output",
    type=Path,
    action="append",
    required=True,
    help="AFL++ output directory, repeatable; missing ones are skipped",
  )
  parser.add_argument(
    "--binary",
    type=Path,
    action="append",
    required=True,
    help="instrumented target, repeatable; each keeps its own coverage",
  )
  parser.add_argument(
    "--corpus",
    type=Path,
    required=True,
    help="corpus directory to replace",
  )
  parser.add_argument(
    "--afl-bin",
    type=Path,
    help="AFL++ tool directory, found when omitted",
  )
  parser.add_argument(
    "--jobs",
    type=int,
    default=DEFAULT_JOBS,
    help=f"parallel afl-tmin runs, {DEFAULT_JOBS} by default",
  )
  return parser.parse_args()


def main() -> int:
  if shutil.which("bash") is None:
    raise FileNotFoundError("afl-cmin.bash needs bash")
  return _reduce(_parse_args())


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
