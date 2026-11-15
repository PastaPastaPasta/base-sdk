#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Print the literals of the `merkleblock_payloads` program."""

from __future__ import annotations

import argparse
from pathlib import Path

from util.rpc import Node, RpcError

# Mainnet block 2,000,000, and for each proof the transactions it matches.
BLOCK_HEIGHT = 2_000_000
BLOCK_HASH = "0000000000000009bd68b5e00976c3f7482d4cc12b6596614fbba5678ef13a59"
FIRST_TXID = "8954c8546a4b19860afaaac95f14fc5909e9593b729b6d8228918d5deacfc222"
LAST_TXID = "ac745767380eac6ba7065a34b460fae44b56d5f2c4f96afba9cdb0ef6d14501e"
MATCHES = {
  "last": ((LAST_TXID,), "its last transaction"),
  "two": ((FIRST_TXID, LAST_TXID), "transactions at both ends"),
}


def render(node: Node) -> str:
  """Return the literals of the program, read from *node*."""
  block_hash = node.call("getblockhash", BLOCK_HEIGHT)
  if block_hash != BLOCK_HASH:
    raise RpcError(f"unexpected block hash {block_hash!r}")
  lines = []
  for label, (txids, matched) in MATCHES.items():
    proof = node.call("gettxoutproof", list(txids), BLOCK_HASH)
    if not isinstance(proof, str):
      raise RpcError(f"gettxoutproof {label} did not return hex")
    lines.extend([
      f"    // Mainnet height {BLOCK_HEIGHT:,}, block hash {BLOCK_HASH}, from"
      f" gettxoutproof for {matched}.",
      f"    constexpr char PROOF_{label.upper()}[] =",
      f'        "{proof}";',
    ])
  return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "--node", nargs=2, required=True, metavar=("HOST:PORT", "COOKIE")
  )
  return parser.parse_args()


def main() -> None:
  args = parse_args()
  print(render(Node(args.node[0], Path(args.node[1]).expanduser())), end="")


if __name__ == "__main__":
  main()
