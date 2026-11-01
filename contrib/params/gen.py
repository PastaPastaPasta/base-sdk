#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Builds the chain-params corpora of pkgs/params/corpus.

Every value comes from a chainparams_dump that build.sh linked against a
reference implementation release. Each dump writes the corpus of its release
line, chainparams_v<major>_<minor>.json5, and together they write
brr_payments.json5.

  gen.py --dump DIR [--dump DIR ...] --out pkgs/params/corpus
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHAINS = ("main", "test", "devnet", "regtest")
BLOCK_VALUE = 1_000_000_000
PERIODS = 19

CHAINPARAMS_HEADER = """\
// Chain parameters of the reference implementation at {tag} ({commit}),
// for dash-params' chain setup test.
//
// "bases" holds the parameters of each chain with no options, as
// contrib/params/chainparams_dump prints them. "params" holds the consensus
// and network parameters, "ext" the chain's other parameters. Each entry is
// the output of the command above it. dash-primitives checks the genesis
// block bytes, dash-params every other value.
//
// Dump source sha256 {source}.
// Regenerate as contrib/params/README.md describes.
"""

PAYMENTS_HEADER = """\
// Masternode payments of the reference implementation on mainnet in the
// classic reward era, for a block value of {value} duffs, around each block
// reward reallocation period, for dash-params' period table test.
//
// "realloc_start" is the first height of the first period and
// "period_blocks" the length of each. Each row is the output of the
// contrib/params/chainparams_dump command beside it, at the release it is
// under, {releases}.
//
// Dump source sha256 {source}.
// Regenerate as contrib/params/README.md describes.
"""


def run(dump: Path, *args: str) -> dict:
  proc = subprocess.run(  # noqa: S603
    [dump / "chainparams_dump", *args],
    capture_output=True,
    text=True,
    check=True,
  )
  return json.loads(proc.stdout)


def release_line(tag: str) -> str:
  m = re.fullmatch(r"v(\d+)\.(\d+)\.\d+(-rc\.\d+)?", tag)
  if m is None:
    sys.exit(f"{tag}: not a release tag")
  return f"v{m[1]}_{m[2]}"


def json_block(value: object, indent: int) -> str:
  text = json.dumps(value, indent=2)
  return text.replace("\n", "\n" + " " * indent)


def chainparams_corpus(dump: Path, info: dict) -> tuple[str, dict]:
  bases = {}
  entries = []
  for chain in CHAINS:
    out = run(dump, "params", chain)
    if "error" in out:
      sys.exit(f"{dump} {chain}: {out['error']}")
    bases[chain] = out
    entries.append(
      f"    // chainparams_dump params {chain}\n"
      f'    "{chain}": {json_block(out, 4)}'
    )
  header = CHAINPARAMS_HEADER.format(
    tag=info["tag"], commit=info["commit"][:12], source=info["source_sha256"]
  )
  body = (
    "{\n"
    f'  "version": {json.dumps(info["version"])},\n'
    '  "bases": {\n' + ",\n".join(entries) + "\n  }\n}\n"
  )
  return header + body, bases["main"]


def payment_heights(main: dict) -> tuple[int, int, tuple[int, ...]]:
  consensus = main["params"]["consensus"]
  brr, cycle = consensus["BRRHeight"], consensus["nSuperblockCycle"]
  start, period = brr - brr % cycle + cycle, 3 * cycle
  heights = [start - 1]
  for i in range(PERIODS):
    heights += [start + i * period, start + (i + 1) * period - 1]
  # One height well past the last period, whose share then holds.
  heights.append(start + 40 * period)
  return start, period, tuple(heights)


def payments_corpus(runs: list[tuple[Path, dict, dict]], source: str) -> str:
  shapes = {payment_heights(main) for _, _, main in runs}
  if len(shapes) != 1:
    sys.exit("the releases disagree on the reallocation periods")
  start, period, heights = shapes.pop()
  sections = []
  for dump, info, _ in runs:
    rows = []
    for height in heights:
      args = ("payment", str(height), str(BLOCK_VALUE))
      out = run(dump, *args)
      row = json.dumps({"height": height, "payment": out["payment"]})
      rows.append(f"      {row}, // chainparams_dump {' '.join(args)}")
    line = release_line(info["tag"])
    sections.append(f'    "{line}": [\n' + "\n".join(rows) + "\n    ]")
  releases = ", ".join(f"{i['tag']} ({i['commit'][:12]})" for _, i, _ in runs)
  header = PAYMENTS_HEADER.format(
    value=BLOCK_VALUE, source=source, releases=releases
  )
  return header + (
    "{\n"
    f'  "realloc_start": {start},\n'
    f'  "period_blocks": {period},\n'
    f'  "block_value": {BLOCK_VALUE},\n'
    '  "payments": {\n' + ",\n".join(sections) + "\n  }\n}\n"
  )


def build_corpora(dumps: list[Path]) -> dict[str, str]:
  source = hashlib.sha256((HERE / "chainparams_dump.cpp").read_bytes())
  texts = {}
  runs = []
  for dump in dumps:
    info = run(dump, "info")
    if info["source_sha256"] != source.hexdigest():
      sys.exit(f"{dump}: built from another chainparams_dump.cpp")
    name = f"chainparams_{release_line(info['tag'])}.json5"
    if name in texts:
      sys.exit(f"{dump}: a second dump of {name}")
    texts[name], main = chainparams_corpus(dump, info)
    runs.append((dump, info, main))
  runs.sort(key=lambda r: release_line(r[1]["tag"]))
  texts["brr_payments.json5"] = payments_corpus(runs, source.hexdigest())
  return texts


def main() -> int:
  ap = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  ap.add_argument("--dump", type=Path, action="append", required=True)
  ap.add_argument("--out", type=Path, required=True)
  args = ap.parse_args()
  for name, text in build_corpora(args.dump).items():
    (args.out / name).write_text(text)
  return 0


if __name__ == "__main__":
  sys.exit(main())
