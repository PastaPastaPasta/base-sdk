#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Run a command against every commit in a range.

Creates a temporary worktree, checks out each commit, runs the
command, records the result, then removes the worktree.

Usage:

  ./contrib/git_filter.py -- cargo fmt --check
  ./contrib/git_filter.py feature -- cargo test -F full
  ./contrib/git_filter.py base_branch feature -- cargo test
  ./contrib/git_filter.py --fast-fail -- cargo clippy
  ./contrib/git_filter.py --env RUSTUP_TOOLCHAIN=nightly-2026-02-01 -- cargo check
"""  # noqa: E501

from __future__ import annotations

import argparse
import atexit
import os
import shlex
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from common import (
  ANSI_BOLD,
  ANSI_GREEN,
  ANSI_RED,
  ANSI_RESET,
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  format_table,
  git_out,
  git_run,
  root_dir,
)

# Grace period for a child process before it is terminated.
_CHILD_SHUTDOWN_TIMEOUT = 5

# Mapping between verdict and coloring.
_STATUS_COLORS = {"PASS": ANSI_GREEN, "FAIL": ANSI_RED}


@dataclass
class CommitResult:
  hash: str
  subject: str
  status: str = "pending"


def _enumerate_commits(base: str, tip: str, cwd: str) -> list[CommitResult]:
  """List commits in base..tip order (oldest first)."""
  out = git_out(cwd, "log", "--reverse", "--format=%H%x00%s", f"{base}..{tip}")
  return [
    CommitResult(*line.split("\0", 1))
    for line in out.splitlines()
    if line.strip()
  ]


def _results_table(commits: list[CommitResult]) -> str:
  """Build a markdown summary table."""
  headers = ("Hash", "Description", "Status")
  rows = [(c.hash[:8], c.subject, c.status) for c in commits]
  return format_table(headers, rows, _STATUS_COLORS)


def _terminate_child(
  child: subprocess.Popen[bytes] | None, sig: int,
) -> None:
  """Forward *sig* to the child's process group and reap it."""
  if child is None or child.poll() is not None:
    return
  try:
    os.killpg(child.pid, sig)
  except OSError:
    return
  try:
    child.wait(timeout=_CHILD_SHUTDOWN_TIMEOUT)
  except subprocess.TimeoutExpired:
    os.killpg(child.pid, signal.SIGKILL)
    child.wait()


def _remove_worktree(root: str, wt_path: str) -> None:
  git_run(root, "worktree", "remove", "--force", wt_path)


def _parse_args() -> argparse.Namespace:
  try:
    sep = sys.argv.index("--")
  except ValueError:
    sep = None

  parser = argparse.ArgumentParser(
    description="Run a command against every commit in a range.",
    usage="%(prog)s [options] [base [tip]] -- <cmd...>",
  )
  parser.add_argument(
    "--fast-fail",
    action="store_true",
    help="stop on first failure, mark rest as SKIP",
  )
  parser.add_argument(
    "--env",
    action="append",
    default=[],
    metavar="K=V",
    help="set environment variable (repeatable)",
  )
  parser.add_argument(
    "refs", nargs="*", metavar="ref", help="base and/or tip ref (0, 1, or 2)"
  )

  if sep is None:
    if "-h" in sys.argv or "--help" in sys.argv:
      parser.parse_args(["--help"])
    parser.error("missing -- separator before command")
  args = parser.parse_args(sys.argv[1:sep])
  args.exec_cmd = sys.argv[sep + 1 :]
  if not args.exec_cmd:
    parser.error("no command after --")
  if len(args.refs) > 2:
    parser.error("too many refs (expected 0-2)")
  return args


def main() -> int:
  args = _parse_args()
  root = str(root_dir())

  refs = args.refs
  base = refs[0] if len(refs) >= 2 else DEFAULT_BASE
  tip = refs[-1] if refs else "HEAD"

  base_hash = git_out(root, "rev-parse", base)
  tip_hash = git_out(root, "rev-parse", tip)
  if base_hash == tip_hash:
    print(f"{base} and {tip} are identical ({base_hash[:8]})")
    return RETCODE_SKIP

  commits = _enumerate_commits(base, tip, root)
  if not commits:
    print(f"no commits in {base}..{tip}")
    return RETCODE_SKIP

  env = os.environ.copy()
  for pair in args.env:
    if "=" not in pair:
      print(f"error: bad --env value: {pair}", file=sys.stderr)
      return RETCODE_ERR
    k, v = pair.split("=", 1)
    if not k:
      print(f"error: empty key in --env value: {pair}", file=sys.stderr)
      return RETCODE_ERR
    env[k] = v

  wt_dir = tempfile.mkdtemp(prefix="git-filter-")
  wt_ready = False
  cleaned = False

  def cleanup() -> None:
    nonlocal cleaned
    if cleaned:
      return
    cleaned = True
    if wt_ready:
      _remove_worktree(root, wt_dir)
    elif os.path.isdir(wt_dir):
      os.rmdir(wt_dir)

  atexit.register(cleanup)
  git_out(root, "worktree", "add", "--detach", "--quiet", wt_dir)
  wt_ready = True
  child: subprocess.Popen[bytes] | None = None
  prev_handlers = {}
  for sig in (signal.SIGINT, signal.SIGTERM):
    prev_handlers[sig] = signal.getsignal(sig)

    def handler(_signum: int, _frame: object, *, s: int = sig) -> None:
      try:
        _terminate_child(child, s)
      finally:
        try:
          cleanup()
        finally:
          signal.signal(s, prev_handlers[s])
          os.kill(os.getpid(), s)
          sys.exit(128 + s)

    signal.signal(sig, handler)

  exec_str = shlex.join(args.exec_cmd)
  n = len(commits)
  print(f"{ANSI_BOLD}running {n} commit(s): {base}..{tip}{ANSI_RESET}")
  print(f"  command: {exec_str}")
  if args.env:
    env_keys = [p.split("=", 1)[0] + "=***" for p in args.env]
    print(f"  env: {' '.join(env_keys)}")
  print()

  failed = False
  try:
    for cr in commits:
      git_out(wt_dir, "checkout", "--quiet", "--force", cr.hash)
      git_out(wt_dir, "clean", "-fdx")
      print(f"--- {cr.hash[:8]} {cr.subject} ---")
      child = subprocess.Popen(  # noqa: S603
        args.exec_cmd,
        cwd=wt_dir,
        env=env,
        start_new_session=True,
      )
      rc = child.wait()
      child = None
      if rc == 0:
        cr.status = "PASS"
      else:
        cr.status = "FAIL"
        failed = True
        if args.fast_fail:
          for rest in commits:
            if rest.status == "pending":
              rest.status = "SKIP"
          break
  finally:
    cleanup()
    atexit.unregister(cleanup)

  print(f"\n{ANSI_BOLD}Program:{ANSI_RESET} {exec_str}")
  print(f"\n{_results_table(commits)}\n")
  return RETCODE_ERR if failed else RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
