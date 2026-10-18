#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Drives probe.c: Dash Core's BLS operations through the consensus oracle.

A script (oracle.h, oracle_bls_exec) loads Core's objects into registers
and runs Core's operations on them; each op returns Core's code and
output bytes. `Probe.call` runs one op on decoded operands.
"""

from __future__ import annotations

import hashlib
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from collections.abc import Iterable

ABI = 14

OK, REJECT, E_DECODE, E_ARG = 0, 1, -1, -4

DECODE, SER, SIGN, PUBLIC_KEY, VERIFY = 0, 1, 2, 3, 4
VERIFY_AGGREGATED, VERIFY_SECURE = 5, 6
AGGREGATE_SK, AGGREGATE_PK, AGGREGATE_SIG, SUB_SIG = 7, 8, 9, 10
AGGREGATE_SECURE, SK_SHARE, PK_SHARE, RECOVER_SIG, DH = 11, 12, 13, 14, 15
IES_ENCRYPT, IES_DECRYPT, IES_DECRYPT_BLOB, HASH_TO_G2 = 16, 17, 18, 19

# Ops that store their result in a destination register.
STORES = {
  DECODE, SIGN, PUBLIC_KEY, AGGREGATE_SK, AGGREGATE_PK, AGGREGATE_SIG,
  SUB_SIG, AGGREGATE_SECURE, SK_SHARE, PK_SHARE, RECOVER_SIG, DH, HASH_TO_G2,
}  # fmt: skip

PK, SIG, SK = 0, 1, 2
EAGER, LAZY = 0, 1


class Obj(bytes):
  """A serialized object operand, decoded eagerly into a register."""

  kind = -1


class Sk(Obj):
  kind = SK


class Pk(Obj):
  kind = PK


class Sig(Obj):
  kind = SIG


class Raw(bytes):
  """An operand written into the script as it is."""


class OracleError(RuntimeError):
  """The probe or the oracle refused a call the generator meant to make."""


def compact(n: int) -> bytes:
  """Core's CompactSize."""
  if n < 0xFD:
    return bytes([n])
  if n <= 0xFFFF:
    return b"\xfd" + n.to_bytes(2, "little")
  if n <= 0xFFFFFFFF:
    return b"\xfe" + n.to_bytes(4, "little")
  return b"\xff" + n.to_bytes(8, "little")


def vec(items: Iterable[bytes]) -> bytes:
  """A std::vector of fixed-size objects (or of blobs, already prefixed)."""
  items = list(items)
  return compact(len(items)) + b"".join(items)


def blob(data: bytes) -> bytes:
  """A std::vector<unsigned char>."""
  return compact(len(data)) + data


def u32(n: int) -> bytes:
  return n.to_bytes(4, "little")


def sha256d(data: bytes) -> bytes:
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def dynbitset(bits: list[bool]) -> bytes:
  """Core's DYNBITSET: the bit count, then the bits packed LSB first."""
  out = bytearray((len(bits) + 7) // 8)
  for i, bit in enumerate(bits):
    if bit:
      out[i // 8] |= 1 << (i % 8)
  return compact(len(bits)) + bytes(out)


class Script:
  """An oracle_bls_exec script; registers are handed out in order."""

  def __init__(self, legacy: bool) -> None:
    self.legacy = legacy
    self.code = bytearray()
    self.regs = 0
    self.ops = 0

  def reg(self) -> int:
    if self.regs == 256:
      msg = "out of registers"
      raise OracleError(msg)
    self.regs += 1
    return self.regs - 1

  def emit(self, op: int, operands: bytes, legacy: bool | None = None) -> None:
    """Appends an op under the script's scheme, or `legacy` if given; an
    op with a destination gets the next register."""
    flag = self.legacy if legacy is None else legacy
    self.code += bytes([op, int(flag)]) + operands
    self.ops += 1
    if op in STORES:
      self.code.append(self.reg())

  def load(self, obj: Obj) -> int:
    self.emit(DECODE, bytes([obj.kind, EAGER]) + blob(obj))
    return self.regs - 1

  def operand(self, arg: object) -> bytes:
    """An operand's script bytes, loading objects into registers."""
    if isinstance(arg, Obj):
      return bytes([self.load(arg)])
    if isinstance(arg, Raw):
      return bytes(arg)
    if isinstance(arg, list) and all(isinstance(a, Obj) for a in arg):
      return vec(bytes([self.load(a)]) for a in arg)
    msg = f"operand of type {type(arg).__name__}"
    raise TypeError(msg)


def hashes(items: Iterable[bytes]) -> Raw:
  return Raw(vec(items))


def blobs(items: Iterable[bytes]) -> Raw:
  return Raw(vec(blob(b) for b in items))


def read_compact(data: bytes, pos: int) -> tuple[int, int]:
  """A CompactSize at pos: its value and the position after it."""
  first = data[pos]
  if first < 0xFD:
    return first, pos + 1
  width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
  end = pos + 1 + width
  return int.from_bytes(data[pos + 1 : end], "little"), end


class Probe:
  """A running probe.c process."""

  def __init__(self, path: str) -> None:
    self.path = path
    self.proc = subprocess.Popen(  # noqa: S603 (the probe is our own build)
      [path],
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,
      text=True,
    )
    abi, version = self._ask("I").split(" ", 1)
    if int(abi) != ABI:
      msg = f"{path}: ABI {abi}, want {ABI}"
      raise OracleError(msg)
    self.core_version = version

  def _ask(self, line: str) -> str:
    stdin, stdout = self.proc.stdin, self.proc.stdout
    if stdin is None or stdout is None:
      msg = "probe pipes closed"
      raise OracleError(msg)
    stdin.write(line + "\n")
    stdin.flush()
    answer = stdout.readline()
    if not answer:
      msg = f"{self.path} exited on: {line[:80]}"
      raise OracleError(msg)
    return answer.rstrip("\n").split("\t", 1)[0]

  def run(self, script: Script) -> list[tuple[int, bytes]]:
    """oracle_bls_exec: Core's code and output for every op."""
    answer = self._ask(f"X {script.code.hex() or '-'}").split()
    ret, out = int(answer[0]), answer[1]
    if ret != OK:
      msg = f"script refused ({ret}): {script.code.hex()[:80]}"
      raise OracleError(msg)
    data = b"" if out == "-" else bytes.fromhex(out)
    records, pos = [], 0
    while pos < len(data):
      status = int.from_bytes(data[pos : pos + 4], "little", signed=True)
      if data[pos + 4 : pos + 8] != bytes(4):
        msg = "a record's reserved field is set (not ABI 14?)"
        raise OracleError(msg)
      n, pos = read_compact(data, pos + 8)
      records.append((status, data[pos : pos + n]))
      pos += n
    if len(records) != script.ops:
      msg = f"{len(records)} records for {script.ops} ops"
      raise OracleError(msg)
    return records

  def call(
    self, op: int, legacy: bool, *args: object, flag: bool | None = None
  ) -> tuple[int, bytes]:
    """One op on its operands, objects decoded first under `legacy` and
    the op run under `flag` (by default the same): Core's code and output,
    or E_DECODE when Core cannot read an object (its register would stay
    empty)."""
    script = Script(legacy)
    operands = b"".join(script.operand(a) for a in args)
    loads = [status for status, _ in self.run(script)]
    if E_DECODE in loads:
      return E_DECODE, b""
    if any(status < 0 for status in loads):
      msg = f"an operand loads with {min(loads)}"
      raise OracleError(msg)
    script.emit(op, operands, flag)
    return self.run(script)[-1]

  def must(self, op: int, legacy: bool, *args: object) -> bytes:
    """An op Core must accept."""
    ret, out = self.call(op, legacy, *args)
    if ret != OK:
      msg = f"op {op} returned {ret}"
      raise OracleError(msg)
    return out

  def holds(
    self, op: int, legacy: bool, *args: object, flag: bool | None = None
  ) -> bool:
    """A verification op's verdict; any other code is a generator bug."""
    ret, _ = self.call(op, legacy, *args, flag=flag)
    if ret not in (OK, REJECT):
      msg = f"op {op} returned {ret}"
      raise OracleError(msg)
    return ret == OK

  def decode(
    self, kind: int, mode: int, legacy: bool, raw: bytes
  ) -> tuple[int, bool, bytes]:
    """oracle_bls_decode: code, validity and re-serialization."""
    answer = self._ask(f"D {kind} {mode} {int(legacy)} {raw.hex() or '-'}")
    ret, valid, out = answer.split()
    return int(ret), valid == "1", b"" if out == "-" else bytes.fromhex(out)

  def close(self) -> None:
    if self.proc.stdin is not None:
      self.proc.stdin.close()
    self.proc.wait()
