#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Print live `clsig` and `isdlock` literals for the corpus programs."""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
from pathlib import Path

CHAINS = {"main": "Mainnet", "test": "Testnet"}
MAX_LOCK_QUERY = 100
RPC_TIMEOUT = 600


class RpcError(Exception):
  """A failed call, or a reply without the expected members."""


def is_loopback(host: str) -> bool:
  """Whether *host* is `localhost` or a loopback address."""
  if host == "localhost":
    return True
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
      raise RpcError(f"{host} is not a loopback address")
    token = base64.b64encode(cookie.read_bytes().strip()).decode()
    self.host = host
    self.port = int(port)
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


def render(node: Node) -> str:
  """Return literals for the live locks held by *node*."""
  info = node.call("getblockchaininfo")
  title = CHAINS.get(info.get("chain")) if isinstance(info, dict) else None
  if title is None:
    raise RpcError("the node is on neither mainnet nor testnet")
  chainlock = node.call("getbestchainlock")
  if not isinstance(chainlock, dict) or not isinstance(
      chainlock.get("hex"), str
  ):
    raise RpcError("getbestchainlock did not return a hex payload")
  block_hash = chainlock.get("blockhash")
  height = chainlock.get("height")
  if not isinstance(block_hash, str) or not isinstance(height, int):
    raise RpcError("getbestchainlock did not return a block and height")
  comment = (
    f"    // {title} height {height:,}, block hash {block_hash}, "
    "from getbestchainlock."
  )
  lines = [
    comment,
    "    constexpr char CLSIG_LIVE[] =",
    f'        "{chainlock["hex"]}";',
  ]
  txids = node.call("getrawmempool")
  if not isinstance(txids, list) or not all(
      isinstance(txid, str) for txid in txids
  ):
    raise RpcError("getrawmempool did not return transaction ids")
  found = []
  for start in range(0, len(txids), MAX_LOCK_QUERY):
    locks = node.call("getislocks", txids[start:start + MAX_LOCK_QUERY])
    if not isinstance(locks, list):
      raise RpcError("getislocks did not return an array")
    for lock in locks:
      if not isinstance(lock, dict):
        continue
      txid = lock.get("txid")
      inputs = lock.get("inputs")
      if not isinstance(txid, str) or not isinstance(inputs, list):
        raise RpcError("getislocks returned an incomplete lock")
      if isinstance(lock.get("hex"), str):
        found.append(lock)
  one = next((lock for lock in found if len(lock["inputs"]) == 1), None)
  many = max(found, key=lambda lock: len(lock["inputs"]), default=None)
  if one is None or many is None or len(many["inputs"]) < 2:
    raise RpcError("the mempool holds no locks with one and with more inputs")
  for label, lock in (("ONE", one), ("MANY", many)):
    txid = lock["txid"]
    inputs = lock["inputs"]
    count = "one input" if len(inputs) == 1 else f"{len(inputs)} inputs"
    lines.extend([
      f"    // {title} txid {txid}, {count}, from getislocks.",
      f"    constexpr char ISDLOCK_LIVE_{label}[] =",
      f'        "{lock["hex"]}";',
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
