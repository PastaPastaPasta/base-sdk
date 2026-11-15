# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""A JSON-RPC client of one node, for the scripts that read chain data."""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from pathlib import Path

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
