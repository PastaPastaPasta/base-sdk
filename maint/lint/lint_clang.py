#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Check (and apply) clang-format styling, and lint with clang-tidy."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from common import (
  CXX_HEADERS,
  CXX_UNITS,
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  cxx_environ,
  cxx_flags,
  declare_verbs,
  formatted,
  relay,
  repo_files,
  require_bin,
  root_dir,
  touched,
)

# Base name of this script (equivalent to argv[0]).
SCRIPT = Path(__file__).stem

# Progress and summary lines clang-tidy prints per unit, naming no fault.
_NOISE_RE = re.compile(
  r"^(\[\d+/\d+\] Processing file .*"
  r"|\d+ warnings?( and \d+ errors?)? generated\.)$",
)


def _sources(repo_root: Path, only: list[str] | None) -> list[Path]:
  """Return the C and C++ files to lint, or just *only* when given."""
  if only is not None:
    return [repo_root / name for name in only]
  return repo_files(repo_root, *(f"*{s}" for s in CXX_UNITS + CXX_HEADERS))


def _check_format(
  repo_root: Path,
  sources: list[Path],
  *,
  fix: bool,
  scoped: bool,
) -> int | None:
  """Format or check *sources*, or None when clang-format is absent."""
  try:
    clang_format = require_bin("clang-format")
  except FileNotFoundError as e:
    print(f"{e}, skipping the format check", file=sys.stderr)
    return None

  style = repo_root / "maint" / ".clang-format"
  return formatted(
    SCRIPT,
    "C/C++ file",
    sources,
    lambda paths: [
      clang_format,
      f"--style=file:{style}",
      *(["-i"] if fix else ["--dry-run", "--Werror"]),
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=scoped,
    cwd=repo_root,
    output=lambda out, err: relay(out + err, repo_root, stream=sys.stderr),
  )


def _check_tidy(repo_root: Path, sources: list[Path]) -> int | None:
  """Lint the units among *sources*, or None when none could be linted."""
  try:
    clang_tidy = require_bin("clang-tidy")
  except FileNotFoundError as e:
    print(f"{e}, skipping the lint", file=sys.stderr)
    return None

  units = [s for s in sources if s.suffix in CXX_UNITS]
  if not units:
    print(f"{SCRIPT}: no C/C++ unit was touched")
    return RETCODE_PASS

  # Units sharing flags share one run.
  groups: dict[tuple[str, ...], list[Path]] = {}
  for unit in units:
    try:
      flags = cxx_flags(repo_root, unit)
    except FileNotFoundError as e:
      name = unit.relative_to(repo_root)
      print(f"{e}, skipping the lint of {name}", file=sys.stderr)
      continue
    groups.setdefault(tuple(flags), []).append(unit)

  config = repo_root / "maint" / ".clang-tidy"
  env = cxx_environ()
  linted = 0
  failed = False
  for flags, members in groups.items():
    result = subprocess.run(  # noqa: S603
      [
        clang_tidy,
        "--quiet",
        f"--config-file={config}",
        *[str(m) for m in members],
        "--",
        *flags,
      ],
      capture_output=True,
      check=False,
      cwd=str(repo_root),
      env=env,
      text=True,
    )
    relay(
      result.stdout + result.stderr,
      repo_root,
      stream=sys.stderr,
      drop=lambda line: _NOISE_RE.match(line) is not None,
    )
    linted += len(members)
    failed = failed or result.returncode != 0

  if failed:
    return RETCODE_ERR
  if not linted:
    return None
  print(f"{SCRIPT}: {linted} C/C++ unit(s) clean")
  return RETCODE_PASS


def main() -> int:
  args = declare_verbs(
    __doc__ or "",
    {
      "check": "report every fault, changing nothing",
      "apply": f"also rewrite C/C++ this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every C/C++ file in the tree",
    },
  ).parse_args()
  fix = args.verb.startswith("apply")
  repo_root = root_dir()
  only = (
    touched(repo_root, CXX_UNITS + CXX_HEADERS)
    if args.verb == "apply"
    else None
  )
  sources = _sources(repo_root, only)

  verdicts: list[int | None] = [
    _check_format(repo_root, sources, fix=fix, scoped=only is not None),
    _check_tidy(repo_root, sources),
  ]
  ran = [v for v in verdicts if v is not None]
  if not ran:
    return RETCODE_SKIP
  return RETCODE_ERR if any(v != RETCODE_PASS for v in ran) else RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
