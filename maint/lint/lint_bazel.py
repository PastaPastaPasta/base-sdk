#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate Bazel's build definitions (in Starlark) with buildifier."""

from __future__ import annotations

import sys
from pathlib import Path

from common import (
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_SKIP,
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

# Spellings of a Starlark file buildifier understands.
STARLARK_SUFFIXES: tuple[str, ...] = (".bazel", ".bzl")


def _check_format(
  repo_root: Path,
  *,
  fix: bool,
  only: list[str] | None = None,
) -> int | None:
  """Format and lint Starlark, or None when buildifier is absent."""
  try:
    buildifier = require_bin("buildifier")
  except FileNotFoundError as e:
    print(f"{e}, skipping the Starlark check", file=sys.stderr)
    return None

  sources = (
    repo_files(repo_root, *(f"*{s}" for s in STARLARK_SUFFIXES))
    if only is None
    else [Path(n) for n in only]
  )
  mode = "fix" if fix else "check"
  return formatted(
    SCRIPT,
    "Starlark file",
    sources,
    lambda paths: [
      buildifier,
      f"--mode={mode}",
      f"--lint={'fix' if fix else 'warn'}",
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=only is not None,
    cwd=repo_root,
    output=lambda out, err: (
      relay(out, repo_root),
      relay(err, repo_root, stream=sys.stderr),
    ),
  )


def main() -> int:
  args = declare_verbs(
    "Validate Starlark.",
    {
      "check": "report every Starlark fault, changing nothing",
      "apply": f"also rewrite Starlark this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every Starlark file in the tree",
    },
  ).parse_args(sys.argv[1:])
  repo_root = root_dir()

  fix = args.verb.startswith("apply")
  only = touched(repo_root, STARLARK_SUFFIXES) if args.verb == "apply" else None
  verdict = _check_format(repo_root, fix=fix, only=only)

  return RETCODE_SKIP if verdict is None else verdict


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
