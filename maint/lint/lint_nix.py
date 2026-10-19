#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Check (and apply) RFC 166 styling for Nix definitions."""

from __future__ import annotations

import sys
from pathlib import Path

from common import (
  RETCODE_ERR,
  RETCODE_SKIP,
  declare_verbs,
  format_verbs,
  formatted,
  repo_files,
  require_bin,
  root_dir,
  touched,
)

SCRIPT = Path(__file__).stem


def _sources(repo_root: Path, only: list[str] | None) -> list[Path]:
  """Return the Nix files to lint, or just *only* when given."""
  if only is not None:
    return [repo_root / name for name in only]
  return repo_files(repo_root, "*.nix")


def main() -> int:
  args = declare_verbs(__doc__ or "", format_verbs("Nix file")).parse_args()

  try:
    nixfmt_bin = require_bin("nixfmt")
  except FileNotFoundError as e:
    print(f"{e}, skipping", file=sys.stderr)
    return RETCODE_SKIP

  repo_root = root_dir()
  fix = args.verb.startswith("apply")
  only = touched(repo_root, (".nix",)) if args.verb == "apply" else None
  sources = _sources(repo_root, only)

  return formatted(
    SCRIPT,
    "Nix file",
    sources,
    lambda paths: [
      nixfmt_bin,
      *([] if fix else ["--check"]),
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=only is not None,
    cwd=repo_root,
  )


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
