#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Runs semgrep rules against the workspace."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from pathlib import Path

from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  SOURCE_DIRS,
  repo_files,
  require_bin,
  root_dir,
)

# Root the per-language rule directories sit under.
CONFIG_ROOT = ("maint", "semgrep")

# Pathspecs each language's rules are scanned against.
LANGUAGES: dict[str, tuple[str, ...]] = {
  "rust": SOURCE_DIRS,
}


def _scan(
  semgrep_bin: str,
  repo_root: Path,
  directory: str,
  wheres: tuple[str, ...],
) -> int | None:
  """Scan one language, or None when it declares no rules."""
  config_dir = repo_root.joinpath(*CONFIG_ROOT, directory)

  configs: list[str] = []
  for cfg in sorted(config_dir.rglob("*.yml")):
    configs.extend(["--config", str(cfg)])

  if not configs:
    print(f"no semgrep rules for {directory}, skipping", file=sys.stderr)
    return None

  print(f"checking {directory}: {len(configs) // 2} rule file(s)")
  result = subprocess.run(  # noqa: S603
    [
      semgrep_bin,
      "scan",
      *configs,
      "--error",
      *[str(p) for p in repo_files(repo_root, *wheres)],
    ],
    check=False,
  )
  return RETCODE_PASS if result.returncode == 0 else RETCODE_ERR


def main() -> int:
  semgrep_bin = require_bin("semgrep")
  repo_root = root_dir()

  root = repo_root.joinpath(*CONFIG_ROOT)
  stray = sorted(
    d.name for d in root.iterdir() if d.is_dir() and d.name not in LANGUAGES
  )
  if stray:
    raise FileNotFoundError(
      f"no language claims the semgrep rules in: {', '.join(stray)}",
    )

  verdicts = [
    _scan(semgrep_bin, repo_root, directory, wheres)
    for directory, wheres in LANGUAGES.items()
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
