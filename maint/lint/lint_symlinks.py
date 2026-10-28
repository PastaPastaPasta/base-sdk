#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate symbolic link integrity.

All symbolic links must meet these criteria:
- They must be a soft link (hard-links are filesystem-level, not file-level)
- They must use relative paths (to prevent them from breaking in containers)
- They must not dangle (i.e. point to non-existent resources)
- They must not have a depth >1 (i.e. cannot point to another symlink)
- They must not point to resources outside the repository (to prevent escapes)
- They must not appear inside a publishable crate directory (`pkgs/`)
"""

from __future__ import annotations

import posixpath
import shutil
import subprocess
import sys
from pathlib import Path

_GIT = shutil.which("git") or "git"

# Mode the index records for a symlink, and the two it records for a file.
_MODE_LINK = "120000"
_MODE_FILE = ("100644", "100755")


def _git_out(cwd: Path, *args: str) -> str:
  """Run a git command in *cwd*, raise on failure, return its output.

  Output is handed back as git wrote it, since a link target can hold
  leading or trailing whitespace that a strip would silently repair.
  """
  result = subprocess.run(  # noqa: S603
    [_GIT, *args],
    capture_output=True,
    check=False,
    cwd=str(cwd),
    text=True,
  )
  if result.returncode != 0:
    fault = result.stderr.strip() or result.stdout.strip()
    raise RuntimeError(f"git {args[0]}: {fault or result.returncode}")
  return result.stdout


def _tracked(repo_root: Path) -> list[tuple[str, str, str]]:
  """Return `(mode, blob, path)` for every entry the index holds."""
  entries: list[tuple[str, str, str]] = []
  for record in _git_out(repo_root, "ls-files", "-s", "-z").split("\0"):
    if not record:
      continue
    meta, _, path = record.partition("\t")
    mode, blob = meta.split()[:2]
    entries.append((mode, blob, path))
  return entries


def _link_fault(
  repo_root: Path,
  modes: dict[str, str],
  path: str,
  target: str,
) -> str | None:
  """Return why *path* is an unacceptable link, or None when it is fine."""
  if posixpath.isabs(target):
    return "absolute target"
  dest = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
  if dest == ".." or dest.startswith("../"):
    return "target outside the repository"
  if dest not in modes:
    return "target is not tracked"
  if modes[dest] == _MODE_LINK:
    return "target is itself a link"
  if not (repo_root / dest).exists():
    return "target is missing on disk"
  return None


def _hard_link_fault(repo_root: Path, path: str) -> str | None:
  """Return if *path* is hard linked, or None when it holds one name."""
  try:
    names = (repo_root / path).lstat().st_nlink
  except OSError:
    return None
  return f"hard linked, {names} names" if names > 1 else None


def main() -> int:
  here = Path(__file__).resolve().parent
  repo_root = Path(_git_out(here, "rev-parse", "--show-toplevel").strip())
  entries = _tracked(repo_root)
  modes = {path: mode for mode, _, path in entries}

  faults: list[str] = []
  for mode, blob, path in sorted(entries, key=lambda entry: entry[2]):
    if mode == _MODE_LINK:
      target = _git_out(repo_root, "cat-file", "blob", blob)
      fault = _link_fault(repo_root, modes, path, target)
      if fault is not None:
        faults.append(f"{path} -> {target}: {fault}")
      elif path.startswith("pkgs/"):
        faults.append(
          f"{path} -> {target}: symlink inside a publishable crate directory "
          "is prohibited",
        )
    elif mode in _MODE_FILE:
      fault = _hard_link_fault(repo_root, path)
      if fault is not None:
        faults.append(f"{path}: {fault}")

  for fault in faults:
    print(fault, file=sys.stderr)
  return 1 if faults else 0


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(1)
