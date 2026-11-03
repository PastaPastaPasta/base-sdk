#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Write the block reward reallocation payment corpus.

For the first and last block of each block reward reallocation period before
`v20`, the corpus holds the block value and the masternode payment from it, on
mainnet and testnet. The params tests check `BRR_PERIODS_PERMILLE` against
these payments. Each node needs `-txindex`.

Usage:

  ./pkgs/params/contrib/brr_payments.py \\
    --node 127.0.0.1:9998 ~/.dashcore/.cookie \\
    --node 127.0.0.1:19998 ~/.dashcore/testnet3/.cookie \\
    --max-height main 1877608 \\
    --release dashcore-24.0.0-rc.5-x86_64-linux-gnu.tar.gz
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import sys
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

# Where the corpus is written by default.
CORPUS = (
  Path(__file__).resolve().parent.parent / "corpus" / "brr_payments.json5"
)

# The chains the corpus holds, as nodes name them.
CORPUS_CHAINS = ["main", "test"]

# Reallocation periods with a share of their own; the last share then holds.
PERIODS = 19

# Superblock cycles in a reallocation period.
CYCLES_PER_PERIOD = 3

# The highest mainnet height written.
MAINNET_MAX_HEIGHT = 2_077_000

# Seconds to wait for a reply.
RPC_TIMEOUT = 600


class RpcError(Exception):
  """A failed call, or a reply without the expected members."""


def is_loopback(host: str) -> bool:
  """Whether *host* is `localhost` or a loopback address."""
  if host == "localhost":
    return True
  # An IPv6 address in a host:port pair comes in brackets.
  if host.startswith("[") and host.endswith("]"):
    host = host[1:-1]
  try:
    return ipaddress.ip_address(host).is_loopback
  except ValueError:
    return False


class Node:
  """A JSON-RPC client of one node, authenticated with its cookie."""

  def __init__(self, address: str, cookie: Path) -> None:
    host, _, port = address.rpartition(":")
    if not host or not port.isdigit():
      raise RpcError(f"{address!r} is not a host:port address")
    if not is_loopback(host):
      hint = "reach a remote node through a tunnel"
      raise RpcError(f"{host} is not a loopback address; {hint}")
    self.host = host
    self.port = int(port)
    token = base64.b64encode(cookie.read_bytes().strip()).decode()
    self.headers = {
      "Authorization": f"Basic {token}",
      "Content-Type": "application/json",
    }

  def call(self, method: str, *params: object) -> object:
    """Return the result of RPC *method* with *params*."""
    body = json.dumps({"id": 0, "method": method, "params": list(params)})
    conn = http.client.HTTPConnection(self.host, self.port, timeout=RPC_TIMEOUT)
    try:
      conn.request("POST", "/", body, self.headers)
      response = conn.getresponse()
      data = response.read()
    except http.client.HTTPException as err:
      raise RpcError(f"{method}: {err!r}") from err
    finally:
      conn.close()
    if response.status == http.client.UNAUTHORIZED:
      raise RpcError(f"{method}: the cookie was refused")
    # The node sends an error with another status and a JSON body naming it,
    # so the body is decoded before the status is checked.
    try:
      reply = json.loads(data)
    except ValueError:
      reply = None
    error = reply.get("error") if isinstance(reply, dict) else None
    if error is not None:
      raise RpcError(f"{method}: {error!r:.300}")
    if response.status != http.client.OK or not isinstance(reply, dict):
      raise RpcError(f"{method}: HTTP {response.status}, {data[:300]!r}")
    return reply.get("result")


def field(obj: object, key: str, kind: type[T]) -> T:
  """Return member *key* of the JSON object *obj*, checked to be a *kind*."""
  value = obj.get(key) if isinstance(obj, dict) else None
  # Python reads a JSON boolean as an int, so an int member refuses one.
  if not isinstance(value, kind) or (isinstance(value, bool) and kind is int):
    raise RpcError(f"{key!r} is not a {kind.__name__} in {obj!r:.300}")
  return value


def heights(
  node: Node, chain: str, tip: int, max_height: int | None
) -> list[int]:
  """Return the first and last height of each period the corpus covers."""
  deployments = field(node.call("getdeploymentinfo"), "deployments", dict)
  brr = field(field(deployments, "realloc", dict), "height", int)
  v20 = field(field(deployments, "v20", dict), "height", int)
  cycle = field(node.call("getgovernanceinfo"), "superblockcycle", int)
  # The first period starts with the first superblock cycle after `realloc`.
  start = brr - brr % cycle + cycle
  period = CYCLES_PER_PERIOD * cycle
  if max_height is not None and max_height > tip:
    raise RpcError(f"--max-height {max_height} is above the {chain} tip {tip}")
  top = tip if max_height is None else max_height
  found = []
  for index in range(PERIODS):
    first = start + index * period
    found += [h for h in (first, first + period - 1) if h < v20 and h <= top]
  if chain == "main" and found and found[-1] > MAINNET_MAX_HEIGHT:
    raise RpcError(
      f"refusing mainnet height {found[-1]} above {MAINNET_MAX_HEIGHT}"
    )
  return found


def payment(node: Node, height: int) -> dict[str, int]:
  """Return the corpus row of the block at *height*."""
  block_hash = node.call("getblockhash", height)
  stats = node.call("getblockstats", block_hash, ["subsidy", "totalfee"])
  value = field(stats, "subsidy", int) + field(stats, "totalfee", int)
  blocks = node.call("masternode", "payments", block_hash, 1)
  if not isinstance(blocks, list) or len(blocks) != 1:
    raise RpcError(f"masternode payments {height}: {blocks!r:.300}")
  block = blocks[0]
  if (
    field(block, "height", int) != height
    or field(block, "blockhash", str) != block_hash
  ):
    raise RpcError(f"masternode payments {height}: {block!r:.300}")
  txs = field(node.call("getblock", block_hash, 2), "tx", list)
  if not txs:
    raise RpcError(f"getblock {height}: no transactions")
  outputs = {
    (
      field(field(out, "scriptPubKey", dict), "hex", str),
      field(out, "valueSat", int),
    )
    for out in field(txs[0], "vout", list)
  }
  for masternode in field(block, "masternodes", list):
    for payee in field(masternode, "payees", list):
      output = (field(payee, "script", str), field(payee, "amount", int))
      if output not in outputs:
        raise RpcError(f"the coinbase at {height} does not pay {output}")
  paid = field(block, "amount", int)
  return {"height": height, "block_value": value, "payment": paid}


def render(
  chains: dict[str, list[dict[str, int]]],
  version: str,
  release: Path | None,
) -> str:
  """Return the corpus text, a comment header and then the rows by chain."""
  lines = [
    "//",
    "// Block reward reallocation payments. Generated by",
    "// pkgs/params/contrib/brr_payments.py with the reference implementation",
    f"// (dashpay/dash {version}).",
  ]
  if release is not None:
    digest = hashlib.sha256(release.read_bytes()).hexdigest()
    lines += [
      "//",
      f"// Release {release.name}, SHA-256",
      f"// {digest}.",
    ]
  lines += [
    "//",
    "// Each row is the block at the first or last height of a reallocation",
    "// period. Its block value is the subsidy plus the fees `getblockstats`",
    "// reports, and its payment the amount `masternode payments` reports,",
    "// which the block's coinbase pays to each payee.",
    "//",
    "// Heights by chain",
    "//",
  ]
  for chain, rows in chains.items():
    first, last = rows[0]["height"], rows[-1]["height"]
    lines.append(f"//   {chain}  {first} to {last}")
  lines += ["//", "", "{", '  "payments": {']
  for index, (chain, rows) in enumerate(chains.items()):
    lines.append(f"    {json.dumps(chain)}: [")
    lines += [
      f"      {json.dumps(row)}{',' if n + 1 < len(rows) else ''}"
      for n, row in enumerate(rows)
    ]
    lines.append("    ]" + ("," if index + 1 < len(chains) else ""))
  lines += ["  }", "}", ""]
  return "\n".join(lines)


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description=__doc__.splitlines()[0] if __doc__ else None
  )
  parser.add_argument(
    "--node",
    nargs=2,
    action="append",
    required=True,
    metavar=("HOST:PORT", "COOKIE"),
    help="RPC address and cookie file of a node, once per chain",
  )
  parser.add_argument(
    "--max-height",
    nargs=2,
    action="append",
    default=[],
    metavar=("CHAIN", "HEIGHT"),
    help="highest height to read on CHAIN, by default the node's tip",
  )
  parser.add_argument(
    "--release",
    type=Path,
    help="release archive the nodes run, recorded with its SHA-256",
  )
  parser.add_argument(
    "--output",
    type=Path,
    help="file to write, by default the corpus, which needs main and test",
  )
  return parser.parse_args()


def main() -> None:
  args = parse_args()
  max_heights: dict[str, int] = {}
  for chain, height in args.max_height:
    if chain in max_heights:
      raise RpcError(f"--max-height given twice for chain {chain}")
    max_heights[chain] = int(height)
  chains: dict[str, list[dict[str, int]]] = {}
  versions = set()
  for address, cookie in args.node:
    node = Node(address, Path(cookie).expanduser())
    info = node.call("getblockchaininfo")
    chain = field(info, "chain", str)
    if chain in chains:
      raise RpcError(f"two nodes on chain {chain}")
    tip = field(info, "blocks", int)
    found = heights(node, chain, tip, max_heights.pop(chain, None))
    if not found:
      raise RpcError(f"no heights to read on chain {chain}")
    chains[chain] = [payment(node, height) for height in found]
    versions.add(field(node.call("getnetworkinfo"), "buildversion", str))
  if max_heights:
    raise RpcError(f"no node on chain {', '.join(max_heights)}")
  output = args.output
  if output is None:
    if sorted(chains) != CORPUS_CHAINS:
      need = " and ".join(CORPUS_CHAINS)
      hint = "give --output to write other chains"
      raise RpcError(f"the corpus needs nodes on {need}; {hint}")
    output = CORPUS
  if len(versions) != 1:
    raise RpcError(f"nodes run different versions {sorted(versions)}")
  version = versions.pop()
  release = args.release
  if release is not None and version.removeprefix("v") not in release.name:
    raise RpcError(f"{release.name} is not the archive of {version}")
  text = render(dict(sorted(chains.items())), version, release)
  output.write_text(text, encoding="latin-1")


if __name__ == "__main__":
  try:
    main()
  except (RpcError, OSError, ValueError) as err:
    sys.exit(f"brr_payments: {err}")
