#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

from __future__ import annotations

import subprocess
import sys

from common import RETCODE_ERR, repo_files, require_bin, root_dir

ESLINT_VERSION = "9.39.3"

DEFAULT_TARGETS: tuple[str, ...] = (
  ".github/scripts",
  "docs/samples",
)


def main() -> int:
  npx_bin = require_bin("npx")

  repo_root = root_dir()
  config_path = repo_root / "maint" / "js" / "eslint.config.mjs"

  if not config_path.is_file():
    raise FileNotFoundError(f"error: eslint config not found: {config_path}")

  targets = repo_files(
    repo_root,
    *(f"{t}/*.{ext}" for t in DEFAULT_TARGETS for ext in ("js", "mjs", "cjs")),
  )

  result = subprocess.run(  # noqa: S603
    [
      npx_bin,
      "--yes",
      f"eslint@{ESLINT_VERSION}",
      "--config",
      str(config_path),
      *[str(p) for p in targets],
    ],
    check=False,
    cwd=str(repo_root),
  )
  return result.returncode


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
