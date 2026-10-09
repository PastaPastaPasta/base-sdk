#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Minimal BLS12-381 arithmetic for building BLS decode test inputs."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from collections.abc import Callable

P = int(
  "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
  "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
  16,
)
R = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

G1_X = int(
  "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905"
  "a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
  16,
)
G1_Y = int(
  "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af6"
  "00db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
  16,
)
G2_X0 = int(
  "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02"
  "b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
  16,
)
G2_X1 = int(
  "13e02b6052719f607dacd3a088274f65596bd0d09920b61a"
  "b5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
  16,
)
G2_Y0 = int(
  "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a7"
  "6d429a695160d12c923ac9cc3baca289e193548608b82801",
  16,
)
G2_Y1 = int(
  "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af"
  "267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
  16,
)


def fp_sqrt(a: int) -> int | None:
  """A square root modulo p, or None for a non-residue (p = 3 mod 4)."""
  root = pow(a % P, (P + 1) // 4, P)
  return root if root * root % P == a % P else None


def fp_inv(a: int) -> int:
  return pow(a % P, P - 2, P)


def fp_sign(v: int) -> int:
  """The IETF sign of an element of Fp: 1 above (p - 1) / 2."""
  return int(v % P > (P - 1) // 2)


class Fp2:
  """An element c0 + c1*u of the quadratic extension, with u^2 = -1."""

  __slots__ = ("c0", "c1")

  def __init__(self, c0: int, c1: int) -> None:
    self.c0 = c0 % P
    self.c1 = c1 % P

  def __add__(self, o: Fp2) -> Fp2:
    return Fp2(self.c0 + o.c0, self.c1 + o.c1)

  def __sub__(self, o: Fp2) -> Fp2:
    return Fp2(self.c0 - o.c0, self.c1 - o.c1)

  def __mul__(self, o: Fp2) -> Fp2:
    return Fp2(self.c0 * o.c0 - self.c1 * o.c1, self.c0 * o.c1 + self.c1 * o.c0)

  def __eq__(self, o: object) -> bool:
    return isinstance(o, Fp2) and (self.c0, self.c1) == (o.c0, o.c1)

  def inv(self) -> Fp2:
    norm_inv = fp_inv(self.c0 * self.c0 + self.c1 * self.c1)
    return Fp2(self.c0 * norm_inv, -self.c1 * norm_inv)

  def is_zero(self) -> bool:
    return self.c0 == 0 and self.c1 == 0

  def sign(self) -> int:
    """The IETF sign: that of c1, or of c0 when c1 is zero."""
    return fp_sign(self.c1 if self.c1 else self.c0)

  def sqrt(self) -> Fp2 | None:
    """A square root, or None for a non-residue."""
    if self.is_zero():
      return Fp2(0, 0)
    if self.c1 == 0:
      root = fp_sqrt(self.c0)
      if root is not None:
        return Fp2(root, 0)
      root = fp_sqrt(-self.c0)
      return None if root is None else Fp2(0, root)
    norm = fp_sqrt(self.c0 * self.c0 + self.c1 * self.c1)
    if norm is None:
      return None
    half = fp_inv(2)
    for delta in ((self.c0 + norm) * half, (self.c0 - norm) * half):
      x0 = fp_sqrt(delta)
      if x0:
        root = Fp2(x0, self.c1 * fp_inv(2 * x0))
        if root * root == self:
          return root
    return None


B2 = Fp2(4, 4)

# An affine point (x, y) over Fp (ints) or Fp2, or None for the identity.
Point = tuple[object, object] | None


def g1_rhs(x: int) -> int:
  return (x * x * x + 4) % P


def g2_rhs(x: Fp2) -> Fp2:
  return x * x * x + B2


def g1_add(a: Point, b: Point) -> Point:
  if a is None:
    return b
  if b is None:
    return a
  (x1, y1), (x2, y2) = a, b
  if x1 == x2:
    if (y1 + y2) % P == 0:
      return None
    lam = 3 * x1 * x1 * fp_inv(2 * y1) % P
  else:
    lam = (y2 - y1) * fp_inv(x2 - x1) % P
  x3 = (lam * lam - x1 - x2) % P
  return (x3, (lam * (x1 - x3) - y1) % P)


def g2_add(a: Point, b: Point) -> Point:
  if a is None:
    return b
  if b is None:
    return a
  (x1, y1), (x2, y2) = a, b
  if x1 == x2:
    if (y1 + y2).is_zero():
      return None
    lam = Fp2(3, 0) * x1 * x1 * (Fp2(2, 0) * y1).inv()
  else:
    lam = (y2 - y1) * (x2 - x1).inv()
  x3 = lam * lam - x1 - x2
  return (x3, lam * (x1 - x3) - y1)


def mul(add: Callable[[Point, Point], Point], base: Point, k: int) -> Point:
  """k times base, by double-and-add."""
  acc: Point = None
  while k:
    if k & 1:
      acc = add(acc, base)
    base = add(base, base)
    k >>= 1
  return acc


def g1_mul(k: int) -> Point:
  """k times the G1 generator."""
  return mul(g1_add, (G1_X, G1_Y), k)


def g2_mul(k: int) -> Point:
  """k times the G2 generator."""
  return mul(g2_add, (Fp2(G2_X0, G2_X1), Fp2(G2_Y0, G2_Y1)), k)


def be(v: int, n: int = 48) -> bytes:
  return v.to_bytes(n, "big")


def with_flags(raw: bytes, flags: int) -> bytes:
  """Replaces the top three bits of the leading byte."""
  return bytes([(raw[0] & 0x1F) | flags]) + raw[1:]


def g2_legacy(x: Fp2, sign: int) -> bytes:
  """Legacy G2 layout: c0 then c1, with the sign in bit 0x80."""
  return with_flags(be(x.c0) + be(x.c1), 0x80 if sign else 0)


def g2_basic(x: Fp2, sign: int) -> bytes:
  """Basic G2 layout: c1 then c0, compression 0x80, sign 0x20."""
  return with_flags(be(x.c1) + be(x.c0), 0x80 | (0x20 if sign else 0))


def g1_legacy_to_basic(raw: bytes) -> bytes:
  """Moves the legacy sign bit 0x80 to 0x20 and sets compression."""
  return with_flags(raw, 0x80 | (0x20 if raw[0] & 0x80 else 0))


def g2_legacy_to_basic(raw: bytes) -> bytes:
  """Swaps c0 || c1 to c1 || c0, moving the sign as for G1."""
  c0 = with_flags(raw[:48], 0)
  return with_flags(raw[48:], 0x80 | (0x20 if raw[0] & 0x80 else 0)) + c0
