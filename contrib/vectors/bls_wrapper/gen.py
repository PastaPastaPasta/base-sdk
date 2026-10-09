#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Builds BLS wrapper vectors from Dash Core's CBLSWrapper.

Inputs come from the seeded class generators below; every outcome comes
from a probe linked against a Dash Core build (see README.md). Passing
probes built from several releases also checks that they agree.

  gen.py corpus --probe A --probe B --out pkgs/pkc/corpus/bls_wrapper.json5
  gen.py fuzz --probe A --count N --seed S --out FILE.jsonl
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import random
import subprocess
import sys
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

import bls12_381 as c

if TYPE_CHECKING:
  from collections.abc import Callable

  Gen = Callable[[random.Random], bytes]
  Eager = dict[str, dict[str, str]]

SEED = 0xB511A7
PAIR_PREPS = (
  "unser:L", "unser:B", "unser:L,get", "unser:B,get", "set:BL", "new:B",
)  # fmt: skip

# The cofactors and the prime powers dividing them; h2 also has a 448-bit
# prime factor.
H1 = int("396c8c005555e1568c00aaab0000aaab", 16)
H2 = int(
  "5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa"
  "628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5",
  16,
)
G1_TORSION = {"3": 3, "11": 11**2, "10177": 10177**2, "859267": 859267**2}
G1_TORSION |= {"52437899": 52437899**2}
G2_TORSION = {"13": 13**2, "23": 23**2, "2713": 2713, "11953": 11953}
G2_TORSION |= {"262069": 262069}
G2_TORSION |= {"big": H2 // math.prod(G2_TORSION.values())}


def below(rng: random.Random, hi: int) -> int:
  return rng.randrange(1, hi)


def ge_p(rng: random.Random) -> int:
  return rng.randrange(c.P, 1 << 381)


def g1_x(rng: random.Random, on_curve: bool) -> int:
  """A random x on or off the G1 curve; on it, almost surely outside the
  subgroup."""
  while True:
    x = below(rng, c.P)
    if (c.fp_sqrt(c.g1_rhs(x)) is not None) == on_curve:
      return x


class SubgroupWalk:
  """Subgroup points P, P + Q, P + 2Q, ... for random P and Q.

  One addition per point rather than a scalar multiplication, which keeps
  large samples fast. P and Q are drawn on first use.
  """

  def __init__(self, mul: Callable[[int], c.Point], add: Callable) -> None:
    self.mul, self.add = mul, add
    self.point: c.Point = None
    self.step: c.Point = None

  def next_point(self, rng: random.Random) -> c.Point:
    if self.point is None:
      self.point = self.mul(below(rng, c.R))
      self.step = self.mul(below(rng, c.R))
    else:
      self.point = self.add(self.point, self.step)
    if self.point is None:
      raise ValueError("identity")
    return self.point

  def next_x(self, rng: random.Random) -> object:
    return self.next_point(rng)[0]


G1_WALK = SubgroupWalk(c.g1_mul, c.g1_add)
G2_WALK = SubgroupWalk(c.g2_mul, c.g2_add)


def g1_sub(rng: random.Random) -> int:
  return G1_WALK.next_x(rng)


class Torsion:
  """Points of order dividing `order`, a factor of the cofactor `h`, as small
  multiples of one base point drawn on first use."""

  def __init__(
    self, add: Callable, walk: SubgroupWalk, h: int, order: int
  ) -> None:
    self.add, self.walk, self.h, self.order = add, walk, h, order
    self.base: c.Point = None

  def sample(
    self,
    rng: random.Random,
    curve_point: Callable[[random.Random], c.Point],
    plus_subgroup: bool,
  ) -> c.Point:
    while self.base is None:
      self.base = c.mul(self.add, curve_point(rng), self.h * c.R // self.order)
    point = None
    while point is None:
      k = rng.randrange(1, min(self.order, 1 << 64))
      point = c.mul(self.add, self.base, k)
    return (
      self.add(point, self.walk.next_point(rng)) if plus_subgroup else point
    )


def g2_x(rng: random.Random, on_curve: bool) -> c.Fp2:
  """A random x on or off the G2 curve."""
  while True:
    x = c.Fp2(rng.randrange(c.P), rng.randrange(c.P))
    if (c.g2_rhs(x).sqrt() is not None) == on_curve:
      return x


def g2_sub(rng: random.Random) -> c.Fp2:
  return G2_WALK.next_x(rng)


def g1_point(rng: random.Random) -> c.Point:
  x = g1_x(rng, True)
  return (x, c.fp_sqrt(c.g1_rhs(x)))


def g2_point(rng: random.Random) -> c.Point:
  x = g2_x(rng, True)
  return (x, c.g2_rhs(x).sqrt())


G1_TORSIONS = {
  name: Torsion(c.g1_add, G1_WALK, H1, order)
  for name, order in G1_TORSION.items()
}
G2_TORSIONS = {
  name: Torsion(c.g2_add, G2_WALK, H2, order)
  for name, order in G2_TORSION.items()
}


def g2_real_y(rng: random.Random) -> c.Fp2:
  """An x on the curve whose points have y in Fp, i.e. y.c1 = 0.

  Solves for x = a + b*u with x^3 + 4 + 4u in Fp: 3a^2 b - b^3 = -4.
  """
  while True:
    b = below(rng, c.P)
    a = c.fp_sqrt((b * b * b - 4) * c.fp_inv(3 * b))
    if a is None:
      continue
    x = c.Fp2(a, b)
    rhs = c.g2_rhs(x)
    if rhs.c1 == 0 and c.fp_sqrt(rhs.c0) is not None:
      return x


def g1_classes() -> dict[str, Gen]:
  sub = g1_sub
  on, off = partial(g1_x, on_curve=True), partial(g1_x, on_curve=False)

  def flags(make: Callable[[random.Random], int], bits: int) -> Gen:
    return lambda rng: c.with_flags(c.be(make(rng)), bits)

  def tail(rng: random.Random) -> bytes:
    return b"\xc0" + bytes(46) + bytes([rng.randrange(1, 256)])

  def torsion(name: str, plus_subgroup: bool) -> Gen:
    def make(rng: random.Random) -> bytes:
      x, y = G1_TORSIONS[name].sample(rng, g1_point, plus_subgroup)
      return c.with_flags(c.be(x), 0x80 | (0x20 if c.fp_sign(y) else 0))

    return make

  torsions = {
    f"tors_{name}{suffix}": torsion(name, suffix == "_sub")
    for name in G1_TORSION
    for suffix in ("", "_sub")
  }
  return torsions | {
    "zero": lambda rng: bytes(48),
    "identity": lambda rng: b"\xc0" + bytes(47),
    "inf_tail": tail,
    "inf_sign": lambda rng: b"\xe0" + bytes(47),
    "inf_x": flags(on, 0xC0),
    "x_eq_p_000": lambda rng: c.be(c.P),
    "x_ge_p_000": flags(ge_p, 0x00),
    "x_ge_p_100": flags(ge_p, 0x80),
    "x_ge_p_101": flags(ge_p, 0xA0),
    "stray_001_sub": flags(sub, 0x20),
    "stray_010_sub": flags(sub, 0x40),
    "stray_011_sub": flags(sub, 0x60),
    "stray_111_sub": flags(sub, 0xE0),
    "stray_001_off": flags(off, 0x20),
    "stray_010_off": flags(off, 0x40),
    "stray_011_off": flags(off, 0x60),
    "sub_000": flags(sub, 0x00),
    "sub_100": flags(sub, 0x80),
    "sub_101": flags(sub, 0xA0),
    "nonsub_000": flags(on, 0x00),
    "nonsub_100": flags(on, 0x80),
    "nonsub_101": flags(on, 0xA0),
    "off_000": flags(off, 0x00),
    "off_100": flags(off, 0x80),
    "off_101": flags(off, 0xA0),
    "x0_100": lambda rng: b"\x80" + bytes(47),
    "x0_101": lambda rng: b"\xa0" + bytes(47),
    "x_max_000": lambda rng: c.be(c.P - 1),
    "x_max_100": lambda rng: c.with_flags(c.be(c.P - 1), 0x80),
    "x_max_101": lambda rng: c.with_flags(c.be(c.P - 1), 0xA0),
    "random": lambda rng: rng.randbytes(48),
  }


def g2_classes() -> dict[str, Gen]:
  on, off = partial(g2_x, on_curve=True), partial(g2_x, on_curve=False)

  def legacy(make: Callable[[random.Random], c.Fp2], sign: int) -> Gen:
    return lambda rng: c.g2_legacy(make(rng), sign)

  def basic(make: Callable[[random.Random], c.Fp2], sign: int) -> Gen:
    return lambda rng: c.g2_basic(make(rng), sign)

  def flags(base: Gen, bits: int) -> Gen:
    return lambda rng: c.with_flags(base(rng), bits)

  def c0_flags(rng: random.Random) -> bytes:
    raw = c.g2_basic(g2_sub(rng), 0)
    return raw[:48] + c.with_flags(raw[48:], 0x20)

  def tail(at: int) -> Gen:
    def make(rng: random.Random) -> bytes:
      out = bytearray(b"\xc0" + bytes(95))
      out[at] = rng.randrange(1, 256)
      return bytes(out)

    return make

  def pair(first_half: bool, bits: int) -> Gen:
    """One coordinate at or above p, in the first or the second half."""

    def make(rng: random.Random) -> bytes:
      bad, good = c.be(ge_p(rng)), c.be(rng.randrange(c.P))
      return c.with_flags(bad + good if first_half else good + bad, bits)

    return make

  def zero_x(rng: random.Random) -> c.Fp2:
    return c.Fp2(0, 0)

  def fp_x(rng: random.Random) -> c.Fp2:
    return c.Fp2(below(rng, c.P), 0)

  def imag_x(rng: random.Random) -> c.Fp2:
    return c.Fp2(0, below(rng, c.P))

  def torsion(name: str, plus_subgroup: bool) -> Gen:
    def make(rng: random.Random) -> bytes:
      x, y = G2_TORSIONS[name].sample(rng, g2_point, plus_subgroup)
      return c.g2_basic(x, y.sign())

    return make

  torsions = {
    f"tors_{name}{suffix}": torsion(name, suffix == "_sub")
    for name in G2_TORSION
    for suffix in ("", "_sub")
  }
  edges = {
    f"{name}_{layout}_s{sign}": make(x, sign)
    for name, x in (("fp_x", fp_x), ("imag_x", imag_x))
    for layout, make in (("legacy", legacy), ("basic", basic))
    for sign in (0, 1)
  }
  return (
    torsions
    | edges
    | {
      "zero": lambda rng: bytes(96),
      "identity": lambda rng: b"\xc0" + bytes(95),
      "inf_tail_hi": tail(47),
      "inf_tail_lo": tail(95),
      "inf_sign": lambda rng: b"\xe0" + bytes(95),
      "inf_x": flags(basic(on, 0), 0xC0),
      "legacy_c0_ge_p": pair(True, 0x00),
      "legacy_c1_ge_p": pair(False, 0x00),
      "basic_c1_ge_p": pair(True, 0x80),
      "basic_c0_ge_p": pair(False, 0x80),
      "basic_c0_flags": c0_flags,
      "stray_001_sub": flags(basic(g2_sub, 0), 0x20),
      "stray_010_sub": flags(basic(g2_sub, 0), 0x40),
      "stray_011_sub": flags(basic(g2_sub, 0), 0x60),
      "stray_111_sub": flags(basic(g2_sub, 0), 0xE0),
      "stray_010_legacy": flags(legacy(g2_sub, 0), 0x40),
      "sub_legacy_s0": legacy(g2_sub, 0),
      "sub_legacy_s1": legacy(g2_sub, 1),
      "sub_basic_s0": basic(g2_sub, 0),
      "sub_basic_s1": basic(g2_sub, 1),
      "nonsub_legacy_s0": legacy(on, 0),
      "nonsub_legacy_s1": legacy(on, 1),
      "nonsub_basic_s0": basic(on, 0),
      "nonsub_basic_s1": basic(on, 1),
      "off_legacy_s0": legacy(off, 0),
      "off_legacy_s1": legacy(off, 1),
      "off_basic_s0": basic(off, 0),
      "off_basic_s1": basic(off, 1),
      "realy_legacy_s0": legacy(g2_real_y, 0),
      "realy_legacy_s1": legacy(g2_real_y, 1),
      "realy_basic_s0": basic(g2_real_y, 0),
      "realy_basic_s1": basic(g2_real_y, 1),
      "x0_legacy_s1": legacy(zero_x, 1),
      "x0_basic_s0": basic(zero_x, 0),
      "x0_basic_s1": basic(zero_x, 1),
      "random": lambda rng: rng.randbytes(96),
    }
  )


def sk_classes() -> dict[str, Gen]:
  def be32(v: int) -> bytes:
    return c.be(v, 32)

  return {
    "zero": lambda rng: bytes(32),
    "one": lambda rng: be32(1),
    "r_minus_1": lambda rng: be32(c.R - 1),
    "r": lambda rng: be32(c.R),
    "r_plus_1": lambda rng: be32(c.R + 1),
    "two_r_minus_1": lambda rng: be32(2 * c.R - 1),
    "two_r": lambda rng: be32(2 * c.R),
    "two_r_plus_1": lambda rng: be32(2 * c.R + 1),
    "max": lambda rng: b"\xff" * 32,
    "below_r": lambda rng: be32(below(rng, c.R)),
    "above_r": lambda rng: be32(rng.randrange(c.R + 1, 1 << 256)),
  }


CLASSES: dict[str, Callable[[], dict[str, Gen]]] = {
  "pk": g1_classes,
  "sig": g2_classes,
  "sk": sk_classes,
}
# Classes with a single possible value.
FIXED = {
  "zero", "identity", "inf_sign", "x_eq_p_000", "x0_100", "x0_101",
  "x_max_000", "x_max_100", "x_max_101", "x0_legacy_s1", "x0_basic_s0",
  "x0_basic_s1", "one", "r_minus_1", "r", "r_plus_1", "two_r_minus_1",
  "two_r", "two_r_plus_1", "max",
}  # fmt: skip
# Each derived class re-encodes the first sample of a legacy class in the
# basic layout: the same element in the other scheme.
DERIVED = {
  "pk": ("sub_000", "sub_000_basic", c.g1_legacy_to_basic),
  "sig": ("sub_legacy_s0", "sub_legacy_s0_basic", c.g2_legacy_to_basic),
}
PAIR_CLASSES = {
  "pk": [
    "zero", "x_ge_p_100", "sub_000", "sub_000_basic", "sub_100", "sub_101",
    "off_100",
  ],
  "sig": [
    "zero", "identity", "sub_legacy_s0", "sub_legacy_s0_basic",
    "sub_basic_s0", "sub_basic_s1", "off_legacy_s0",
  ],
}  # fmt: skip


def run_single(probe: str, lines: list[str]) -> dict[str, object]:
  text = "\n".join(lines) + "\n"
  proc = subprocess.run(  # noqa: S603
    [probe], input=text, capture_output=True, text=True, check=True
  )
  out = {}
  for line in proc.stdout.splitlines():
    rec = json.loads(line)
    out[rec["id"]] = rec["r"]
  if len(out) != len(lines):
    sys.exit(f"{probe}: {len(out)} results for {len(lines)} inputs")
  return out


def run_probes(probes: list[str], lines: list[str]) -> dict[str, object]:
  results = [run_single(p, lines) for p in probes]
  for probe, other in zip(probes[1:], results[1:], strict=True):
    if other != results[0]:
      sys.exit(f"{probe} disagrees with {probes[0]}")
  return results[0]


def check_eager(raw: bytes, r: Eager) -> None:
  """Asserts Core's own invariants on one eager result."""
  for flag in ("legacy", "basic"):
    res = r[flag]
    if res["outcome"] == "valid" and res[flag] != raw.hex():
      sys.exit(f"{flag} decode is valid without a round trip: {raw.hex()}")
    if res["outcome"] == "invalid" and res["ser"] != "00" * len(raw):
      sys.exit(f"invalid {flag} object is not zeros: {raw.hex()}")
  # Unserialize is SetBytes and then the round trip.
  if r["basic"]["outcome"] == "valid" and r["set"] != r["basic"]:
    sys.exit(f"SetBytes disagrees with a valid basic decode: {raw.hex()}")


def set_tag(r: Eager) -> str:
  """I (invalid), V (the object the basic decode yields) or
  V:<legacy serialization>/<basic serialization>."""
  res = r["set"]
  if res["outcome"] == "invalid":
    return "I"
  if res == r["basic"]:
    return "V"
  return f"V:{res['legacy']}/{res['basic']}"


def eager_tag(res: dict[str, str], other: str) -> str:
  """T (throw), I (invalid) or V:<the other scheme's serialization>."""
  if res["outcome"] == "throw":
    return "T"
  if res["outcome"] == "invalid":
    return "I"
  return "V:" + res[other]


def encodings(raw: bytes, r: Eager) -> dict[str, str]:
  """Names for the byte strings a lazy object can produce from `raw`.

  XY is the object the eager decode under X yields, serialized under Y.
  """
  table = {"raw": raw.hex(), "zero": "00" * len(raw)}
  for flag, x in (("legacy", "L"), ("basic", "B")):
    if r[flag]["outcome"] == "valid":
      table[x + "L"] = r[flag]["legacy"]
      table[x + "B"] = r[flag]["basic"]
  return table


def tag_bytes(value: str, table: dict[str, str]) -> str:
  return next((k for k, v in table.items() if v == value), value)


def gen_inputs(rng: random.Random, samples: int) -> dict[str, list]:
  inputs = {}
  for kind, make in CLASSES.items():
    rows = []
    for name, gen in make().items():
      for _ in range(1 if name in FIXED else samples):
        row = (name, gen(rng))
        # Some classes hold few values, such as G1's order-3 torsion.
        if row not in rows:
          rows.append(row)
    if kind in DERIVED:
      source, name, convert = DERIVED[kind]
      first = next(raw for n, raw in rows if n == source)
      rows.append((name, convert(first)))
    inputs[kind] = rows
  return inputs


def eager_entry(name: str, raw: bytes, r: Eager) -> dict[str, str]:
  check_eager(raw, r)
  return {
    "class": name,
    "in": raw.hex(),
    "L": eager_tag(r["legacy"], "basic"),
    "B": eager_tag(r["basic"], "legacy"),
    "SB": set_tag(r),
  }


def pair_cases(kind: str) -> list[tuple[str, str, str, str]]:
  """(a, b, a's ops, b's ops) for every pair of classes and preparations."""
  combos = itertools.combinations_with_replacement(PAIR_CLASSES[kind], 2)
  preps = list(itertools.product(PAIR_PREPS, repeat=2))
  return [(a, b, pa, pb) for a, b in combos for pa, pb in preps]


def build_corpus(probes: list[str], seed: int, samples: int) -> dict:
  # Seeded on purpose: the inputs must be reproducible, not secret.
  inputs = gen_inputs(random.Random(seed), samples)  # noqa: S311
  eager = run_probes(probes, [
    f"E {kind}.{i} {kind} {raw.hex()}"
    for kind, rows in inputs.items()
    for i, (_, raw) in enumerate(rows)
  ])  # fmt: skip

  corpus: dict[str, dict] = {}
  firsts: dict[str, dict[str, tuple[bytes, Eager]]] = {}
  for kind, rows in inputs.items():
    results = [eager[f"{kind}.{i}"] for i in range(len(rows))]
    pairs = list(zip(rows, results, strict=True))
    corpus[kind] = {"eager": [eager_entry(n, raw, r) for (n, raw), r in pairs]}
    firsts[kind] = {}
    for (name, raw), r in pairs:
      firsts[kind].setdefault(name, (raw, r))

  lines = []
  for kind in PAIR_CLASSES:
    hexes = {n: raw.hex() for n, (raw, _) in firsts[kind].items()}
    for i, (a, b, pa, pb) in enumerate(pair_cases(kind)):
      lines.append(f"P {kind}.{i} {kind} {hexes[a]} {pa} {hexes[b]} {pb}")
  lazy = run_probes(probes, lines)

  for kind in PAIR_CLASSES:
    tables = {n: encodings(raw, r) for n, (raw, r) in firsts[kind].items()}
    rows = []
    for i, (a, b, pa, pb) in enumerate(pair_cases(kind)):
      row: dict[str, object] = {"a": [a, pa], "b": [b, pb]}
      for order, o in lazy[f"{kind}.{i}"].items():
        ta, tb = tag_bytes(o["a"], tables[a]), tag_bytes(o["b"], tables[b])
        row[order] = [o["eq"], ta, tb]
      rows.append(row)
    corpus[kind]["pairs"] = rows
  return corpus


def build_fuzz(probe: str, seed: int, count: int) -> list[dict]:
  rng = random.Random(seed)  # noqa: S311
  gens = {kind: list(make().items()) for kind, make in CLASSES.items()}
  kinds = list(gens)
  meta = []
  for i in range(count):
    kind = kinds[i % len(kinds)]
    name, gen = gens[kind][rng.randrange(len(gens[kind]))]
    meta.append((kind, name, gen(rng)))
  res = run_single(probe, [
    f"E f{i} {kind} {raw.hex()}" for i, (kind, _, raw) in enumerate(meta)
  ])  # fmt: skip
  return [
    {"kind": kind, **eager_entry(name, raw, res[f"f{i}"])}
    for i, (kind, name, raw) in enumerate(meta)
  ]


def emit_json5(corpus: dict, header: str) -> str:
  """JSON5 text with one record per line, so diffs stay readable."""

  def section(name: str, rows: list) -> str:
    items = [f"      {json.dumps(row)}" for row in rows]
    return f"    {json.dumps(name)}: [\n" + ",\n".join(items) + "\n    ]"

  kinds = [
    f"  {json.dumps(kind)}: {{\n"
    + ",\n".join(section(n, rows) for n, rows in sections.items())
    + "\n  }"
    for kind, sections in corpus.items()
  ]
  return header.rstrip("\n") + "\n{\n" + ",\n".join(kinds) + "\n}\n"


def main() -> int:
  ap = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  ap.add_argument("mode", choices=["corpus", "fuzz"])
  ap.add_argument("--probe", action="append", required=True)
  ap.add_argument("--seed", type=int, default=SEED)
  ap.add_argument("--samples", type=int, default=3)
  ap.add_argument("--count", type=int, default=10_000)
  ap.add_argument("--header", type=Path, help="JSON5 comment to prepend")
  ap.add_argument("--out", type=Path, required=True)
  args = ap.parse_args()

  if args.mode == "corpus":
    corpus = build_corpus(args.probe, args.seed, args.samples)
    header = args.header.read_text() if args.header else ""
    args.out.write_text(emit_json5(corpus, header))
  else:
    rows = build_fuzz(args.probe[0], args.seed, args.count)
    with args.out.open("w") as f:
      f.writelines(json.dumps(row) + "\n" for row in rows)
  return 0


if __name__ == "__main__":
  sys.exit(main())
