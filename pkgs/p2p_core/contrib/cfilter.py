#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Write the BIP157 corpus from compact filters at selected block heights."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

FILTER_HEIGHTS = (999, 1000, 1001, 1002, 2_000_000)
CFILTER_HEIGHTS = (1000, 2_000_000)
CFHEADER_HEIGHTS = (1000, 1001, 1002)
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
  """Return member *key* of *obj*, checked to be a *kind*."""
  value = obj.get(key) if isinstance(obj, dict) else None
  if not isinstance(value, kind) or (isinstance(value, bool) and kind is int):
    raise RpcError(f"{key!r} is not a {kind.__name__} in {obj!r:.300}")
  return value


def compact_size(value: int) -> bytes:
  """Encode a CompactSize value."""
  if value < 253:
    return bytes([value])
  if value <= 0xFFFF:
    return b"\xfd" + value.to_bytes(2, "little")
  if value <= 0xFFFF_FFFF:
    return b"\xfe" + value.to_bytes(4, "little")
  return b"\xff" + value.to_bytes(8, "little")


def wire_hash(value: str) -> bytes:
  """Return a displayed hash in wire byte order."""
  return bytes.fromhex(value)[::-1]


def filter_hash(filter_bytes: bytes) -> str:
  """Return a filter hash in displayed byte order."""
  digest = hashlib.sha256(hashlib.sha256(filter_bytes).digest()).digest()
  return digest[::-1].hex()


def cfilter_rows(node: Node) -> dict[str, dict[str, dict[str, object]]]:
  """Return chain-backed BIP157 rows."""
  block_hashes: dict[int, str] = {}
  filters: dict[int, str] = {}
  headers: dict[int, str] = {}
  for height in FILTER_HEIGHTS:
    block_hash = node.call("getblockhash", height)
    if not isinstance(block_hash, str):
      raise RpcError(f"getblockhash {height} did not return a hash")
    result = node.call("getblockfilter", block_hash)
    block_hashes[height] = block_hash
    filters[height] = field(result, "filter", str)
    headers[height] = field(result, "header", str)

  stop_hash = block_hashes[1002]

  def request(filter_type: int, start_height: int) -> dict[str, object]:
    details = {
      "filter_type": filter_type,
      "start_height": start_height,
      "stop_hash": stop_hash,
    }
    raw = (
      bytes([filter_type])
      + start_height.to_bytes(4, "little")
      + wire_hash(stop_hash)
    )
    return {"raw": raw.hex(), "details": details}

  def checkpoint_request(filter_type: int) -> dict[str, object]:
    details = {"filter_type": filter_type, "stop_hash": stop_hash}
    raw = bytes([filter_type]) + wire_hash(stop_hash)
    return {"raw": raw.hex(), "details": details}

  def filter_row(height: int) -> dict[str, object]:
    filter_bytes = bytes.fromhex(filters[height])
    details = {
      "filter_type": 0,
      "block_hash": block_hashes[height],
      "filter": filters[height],
    }
    raw = (
      bytes([0])
      + wire_hash(block_hashes[height])
      + compact_size(len(filter_bytes))
      + filter_bytes
    )
    return {"raw": raw.hex(), "details": details}

  filter_hashes = [
    filter_hash(bytes.fromhex(filters[height])) for height in CFHEADER_HEIGHTS
  ]
  cfheaders_details = {
    "filter_type": 0,
    "stop_hash": stop_hash,
    "previous_filter_header": headers[999],
    "filter_hashes": filter_hashes,
  }
  cfheaders_raw = (
    bytes([0])
    + wire_hash(stop_hash)
    + wire_hash(headers[999])
    + compact_size(len(filter_hashes))
    + b"".join(wire_hash(value) for value in filter_hashes)
  )
  cfcheckpt_details = {
    "filter_type": 0,
    "stop_hash": stop_hash,
    "filter_headers": [headers[1000]],
  }
  cfcheckpt_raw = (
    bytes([0]) + wire_hash(stop_hash) + bytes([1]) + wire_hash(headers[1000])
  )
  return {
    "getcfilters": {
      "basic": request(0, 1001),
      "unknown_type": request(255, 0xFFFF_FFFF),
    },
    "cfilter": {
      f"block_{height}": filter_row(height) for height in CFILTER_HEIGHTS
    },
    "getcfheaders": {
      "basic": request(0, 1001),
      "unknown_type": request(255, 0xFFFF_FFFF),
    },
    "cfheaders": {
      "three": {"raw": cfheaders_raw.hex(), "details": cfheaders_details}
    },
    "getcfcheckpt": {
      "basic": checkpoint_request(0),
      "unknown_type": checkpoint_request(255),
    },
    "cfcheckpt": {
      "one": {"raw": cfcheckpt_raw.hex(), "details": cfcheckpt_details}
    },
  }


def render(node: Node) -> str:
  """Return the BIP157 corpus text."""
  rows = cfilter_rows(node)
  comments = {
    "getcfilters": [
      "Pins a basic request with an asymmetric start height.",
      "Pins an unknown filter type with the same stop block.",
    ],
    "cfilter": {
      "block_1000": (
        "Pins the basic filter of mainnet block 1000, which has one "
        "coinbase transaction."
      ),
      "block_2000000": (
        "Pins the basic filter of mainnet block 2000000, which has several "
        "transactions."
      ),
    },
    "getcfheaders": [
      "Pins a basic request with an asymmetric start height.",
      "Pins an unknown filter type with the same stop block.",
    ],
    "cfheaders": [
      "Pins three consecutive filter hashes for mainnet blocks 1000 through "
      "1002 and the header before them."
    ],
    "getcfcheckpt": [
      "Pins a basic checkpoint request ending at mainnet block 1002.",
      "Pins an unknown filter type with the same stop block.",
    ],
    "cfcheckpt": ["Pins the filter header for mainnet block 1000."],
  }
  lines = [
    "// BIP157 vectors. Generated by pkgs/p2p_core/contrib/cfilter.py.",
    "// Chain data came from a v24.0.0-rc.3 mainnet node at heights 999",
    "// through 1002 and 2,000,000.",
    "// Regenerate with `python3 pkgs/p2p_core/contrib/cfilter.py",
    "// --node HOST:PORT COOKIE`.",
    "",
    "{",
  ]
  for section, entries in rows.items():
    lines.append(f'  "{section}": {{')
    for index, (label, row) in enumerate(entries.items()):
      comment = (
        comments[section][index]
        if section != "cfilter"
        else comments[section][label]
      )
      lines.append(f"    // {comment}")
      comma = "," if index + 1 < len(entries) else ""
      lines.append(f'    "{label}": {{')
      lines.append(f'      "raw": "{row["raw"]}",')
      lines.append(
        f'      "details": '
        f"{json.dumps(row['details'], separators=(', ', ': '))}"
      )
      lines.append(f"    }}{comma}")
    lines.append("  },")
  lines[-1] = "  }"
  lines.append("}")
  return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
  """Parse command-line arguments."""
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "--node", nargs=2, required=True, metavar=("HOST:PORT", "COOKIE")
  )
  parser.add_argument("--output", type=Path)
  return parser.parse_args()


def main() -> None:
  """Fetch chain data and write the BIP157 corpus."""
  args = parse_args()
  root = Path(__file__).resolve().parents[3]
  output = (
    args.output or root / "pkgs" / "p2p_core" / "corpus" / "cfilter.json5"
  )
  output.write_text(
    render(Node(args.node[0], Path(args.node[1]).expanduser())),
    encoding="latin-1",
  )


if __name__ == "__main__":
  main()
