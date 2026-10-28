#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Merge a pull request with its commits and description baked in.

Fetches the pull request from GitHub and merges its head into the checked out
base branch.

Usage:

  ./contrib/git_merge.py 57
  ./contrib/git_merge.py -R dashpay/base-sdk 57
  ./contrib/git_merge.py -B v0.1.x 57
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  git_out,
  git_run,
  require_bin,
  root_dir,
)

# Fields read from `gh pr view`.
_PR_FIELDS = "number,title,body,state,isDraft,baseRefName,headRefOid"

# Fence around the description.
_FENCE = "`````"


def _gh_json(root: str, *args: str) -> dict[str, object]:
  result = subprocess.run(  # noqa: S603
    [require_bin("gh"), *args],
    capture_output=True,
    check=False,
    cwd=root,
    encoding="utf-8",
  )
  if result.returncode != 0:
    raise RuntimeError(f"gh {args[0]}: {result.stderr.strip()}")
  return json.loads(result.stdout)


def _fetch(root: str, url: str, ref: str) -> str:
  """Fetch *ref* from *url* and return the commit it points to."""
  git_out(root, "fetch", "--quiet", url, ref)
  return git_out(root, "rev-parse", "FETCH_HEAD^{commit}")


def _message(pr: dict[str, object], commits: list[tuple[str, ...]]) -> str:
  """Build the merge commit message for *pr*."""
  lines = [f"{pr['title']} (#{pr['number']})", ""]
  lines += [
    f"* [{h[:8]}] {subject} ({author})" for h, subject, author in commits
  ]
  body = str(pr["body"] or "").replace("\r\n", "\n").strip("\n")
  if body:
    lines += ["", "Description:", "", _FENCE, body, _FENCE]
  return "\n".join(lines) + "\n"


def _parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description="Merge a pull request with its description baked in.",
  )
  parser.add_argument(
    "-R",
    metavar="OWNER/REPO",
    help="repository on GitHub (default: as resolved by gh)",
  )
  parser.add_argument(
    "-B",
    "--base",
    metavar="BRANCH",
    help="branch to merge into (default: the pull request's base)",
  )
  parser.add_argument("pr", type=int, help="pull request number")
  return parser.parse_args()


def main() -> int:
  args = _parse_args()
  root = str(root_dir())
  repo = str(
    args.R
    or _gh_json(root, "repo", "view", "--json", "nameWithOwner")[
      "nameWithOwner"
    ]
  )

  pr = _gh_json(
    root, "pr", "view", str(args.pr), "-R", repo, "--json", _PR_FIELDS
  )
  if pr["state"] != "OPEN":
    raise RuntimeError(f"#{args.pr} is {str(pr['state']).lower()}")
  if pr["isDraft"]:
    raise RuntimeError(f"#{args.pr} is a draft")

  base = args.base or str(pr["baseRefName"])
  branch = git_out(root, "rev-parse", "--abbrev-ref", "HEAD")
  if branch != base:
    raise RuntimeError(f"on {branch!r}, check out {base!r} to merge into")
  if git_out(root, "status", "--porcelain", "--untracked-files=no"):
    raise RuntimeError("working tree has uncommitted changes")

  url = f"https://github.com/{repo}.git"
  # A custom base is the merger's own branch, so only the pull request's base
  # is held to its copy on GitHub.
  if base == pr["baseRefName"]:
    base_tip = _fetch(root, url, f"refs/heads/{base}")
    if git_run(
      root, "merge-base", "--is-ancestor", base_tip, "HEAD"
    ).returncode:
      raise RuntimeError(f"{base} is behind {repo}, pull it first")
  head = _fetch(root, url, f"refs/pull/{args.pr}/head")
  # A push between the two reads would merge commits nobody saw listed.
  if head != pr["headRefOid"]:
    raise RuntimeError(f"#{args.pr} changed while fetching, retry")

  out = git_out(
    root, "log", "--reverse", "--format=%H%x00%s%x00%an", f"HEAD..{head}"
  )
  commits = [tuple(line.split("\0")) for line in out.splitlines()]
  if not commits:
    raise RuntimeError(f"#{args.pr} has nothing to merge into {base}")

  with tempfile.NamedTemporaryFile(
    "w", encoding="utf-8", suffix=".txt", delete=False
  ) as f:
    f.write(_message(pr, commits))
  try:
    # Verbatim cleanup keeps the description's blank lines and '#' lines.
    merge = subprocess.run(  # noqa: S603
      [
        require_bin("git"),
        "merge",
        "--no-ff",
        "--no-edit",
        "--cleanup=verbatim",
        "-F",
        f.name,
        head,
      ],
      check=False,
      cwd=root,
    )
  finally:
    os.unlink(f.name)
  if merge.returncode != 0:
    abort = git_run(root, "merge", "--abort")
    if abort.returncode != 0:
      raise RuntimeError(
        f"merging #{args.pr} failed, cancellation failed, recovering manually: "
        f"{abort.stderr.strip()}"
      )
    raise RuntimeError(f"merging #{args.pr} failed, merge aborted")

  print(git_out(root, "log", "-1", "--format=%B"))
  return RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(f"error: {exc}", file=sys.stderr)
    sys.exit(RETCODE_ERR)
