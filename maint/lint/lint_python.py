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


def main() -> int:
  ruff_bin = require_bin("ruff")

  repo_root = root_dir()
  result = subprocess.run(  # noqa: S603
    [ruff_bin, "check", *[str(p) for p in repo_files(repo_root, "*.py")]],
    check=False,
  )
  return result.returncode


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
