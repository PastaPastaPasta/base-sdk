#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Builds BLS vectors whose every outcome comes from Dash Core.

Inputs are derived from fixed labels; each output, verdict and decode
outcome is what Dash Core's own BLS code returns through the consensus
oracle (probe.c, ABI 14). See README.md.

  gen.py --probe PROBE --out-dir pkgs/pkc/corpus/bls_oracle
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import oracle as o

if TYPE_CHECKING:
  from collections.abc import Callable

  Row = dict[str, object]

# BLS12-381's group order.
R = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
SCHEMES = {"legacy": True, "basic": False}
WRAPPER_DIR = Path(__file__).resolve().parent.parent / "bls_wrapper"


def h(*parts: object) -> bytes:
  """A 32-byte value derived from a label."""
  text = "/".join(str(p) for p in parts)
  return hashlib.sha256(b"bs12 " + text.encode()).digest()


def sk_of(*parts: object) -> bytes:
  """A secret key derived from a label, as Core serializes one."""
  v = int.from_bytes(h("sk", *parts), "big") % R
  return (v or 1).to_bytes(32, "big")


def sks(items: list[bytes]) -> list[o.Obj]:
  return [o.Sk(b) for b in items]


def pk_list(items: list[bytes]) -> list[o.Obj]:
  return [o.Pk(b) for b in items]


def sigs(items: list[bytes]) -> list[o.Obj]:
  return [o.Sig(b) for b in items]


class Gen:
  """Generates one scheme's rows through the probe."""

  def __init__(self, probe: o.Probe, legacy: bool) -> None:
    self.p = probe
    self.legacy = legacy

  def must(self, op: int, *args: object) -> bytes:
    return self.p.must(op, self.legacy, *args)

  def holds(self, op: int, *args: object) -> bool:
    return self.p.holds(op, self.legacy, *args)

  def call(self, op: int, *args: object) -> tuple[int, bytes]:
    return self.p.call(op, self.legacy, *args)

  def obj(self, op: int, *args: object) -> str | None:
    """An object op's output, or None where Core yields an invalid one."""
    ret, out = self.call(op, *args)
    if ret == o.OK:
      return out.hex()
    if ret == o.REJECT:
      return None
    msg = f"op {op} returned {ret}"
    raise o.OracleError(msg)

  def pk(self, sk: bytes) -> bytes:
    return self.must(o.PUBLIC_KEY, o.Sk(sk))

  def sign(self, sk: bytes, msg: bytes) -> bytes:
    return self.must(o.SIGN, o.Sk(sk), o.Raw(msg))

  def verify(self, pk: bytes, sig: bytes, msg: bytes) -> bool:
    return self.holds(o.VERIFY, o.Sig(sig), o.Pk(pk), o.Raw(msg))


def hash_to_g2(g: Gen) -> list[Row]:
  msgs = [bytes(32), b"\xff" * 32, bytes(31) + b"\x01"]
  msgs += [h("h2g2", i) for i in range(13)]
  return [
    {"msg": m.hex(), "point": g.must(o.HASH_TO_G2, o.Raw(m)).hex()}
    for m in msgs
  ]


def flip_sign(raw: bytes, legacy: bool) -> bytes:
  """The negated point: the scheme's sign bit toggled."""
  out = bytearray(raw)
  out[0] ^= 0x80 if legacy else 0x20
  return bytes(out)


def sign_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "sign", i) for i in range(8)]
  pks = [g.pk(sk) for sk in keys]
  msgs = [h("sign msg", i) for i in range(2)]
  sign, verify = [], []
  for i, sk in enumerate(keys):
    for m in msgs:
      sig = g.sign(sk, m)
      sign.append({"key": i, "msg": m.hex(), "sig": sig.hex()})

  def check(pk: bytes, sig: bytes, msg: bytes, note: str) -> None:
    ok = g.verify(pk, sig, msg)
    verify.append(
      {"pk": pk.hex(), "sig": sig.hex(), "msg": msg.hex(), "ok": ok,
       "note": note}
    )  # fmt: skip

  for i, row in enumerate(sign[:8]):
    sig, msg = bytes.fromhex(str(row["sig"])), bytes.fromhex(str(row["msg"]))
    pk = pks[int(str(row["key"]))]
    check(pk, sig, msg, "signed")
    check(pk, sig, h("sign wrong", i), "other message")
    check(pks[(int(str(row["key"])) + 1) % 8], sig, msg, "other key")
    check(pk, flip_sign(sig, g.legacy), msg, "negated signature")
    check(flip_sign(pk, g.legacy), sig, msg, "negated key")
  check(bytes(48), bytes.fromhex(str(sign[0]["sig"])), msgs[0], "zero key")
  check(pks[0], bytes(96), msgs[0], "zero signature")
  return {
    "keys": [
      {"sk": sk.hex(), "pk": pk.hex()} for sk, pk in zip(keys, pks, strict=True)
    ],
    "sign": sign,
    "verify": verify,
  }


def aggregate_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "agg", i) for i in range(6)]
  pks = [g.pk(sk) for sk in keys]
  msg = h("agg msg")
  same = [g.sign(sk, msg) for sk in keys]
  msgs = [h("agg msg", i) for i in range(6)]
  distinct = [g.sign(sk, m) for sk, m in zip(keys, msgs, strict=True)]
  out: dict[str, list[Row]] = {
    "sk": [], "pk": [], "sig": [], "sub": [], "same_msg": [], "distinct": [],
  }  # fmt: skip
  for n in range(1, 7):
    out["sk"].append(
      {
        "sks": [k.hex() for k in keys[:n]],
        "agg": g.obj(o.AGGREGATE_SK, sks(keys[:n])),
      }
    )
    agg_pk = g.must(o.AGGREGATE_PK, pk_list(pks[:n]))
    out["pk"].append({"pks": [p.hex() for p in pks[:n]], "agg": agg_pk.hex()})
    agg = g.must(o.AGGREGATE_SIG, sigs(same[:n]))
    out["sig"].append({"sigs": [s.hex() for s in same[:n]], "agg": agg.hex()})
    # Core's same-message check: VerifyInsecure against the summed key.
    for m, note in ((msg, "signed"), (h("agg wrong"), "other message")):
      out["same_msg"].append({
        "pks": [p.hex() for p in pks[:n]], "sig": agg.hex(), "msg": m.hex(),
        "ok": g.verify(agg_pk, agg, m), "note": note,
      })  # fmt: skip
    dagg = g.must(o.AGGREGATE_SIG, sigs(distinct[:n]))
    cases = [(msgs[:n], "signed")]
    cases.append(([h("agg wrong"), *msgs[1:n]], "first message changed"))
    for ms, note in cases:
      ok = g.holds(
        o.VERIFY_AGGREGATED, o.Sig(dagg), pk_list(pks[:n]), o.hashes(ms)
      )
      out["distinct"].append({
        "pks": [p.hex() for p in pks[:n]], "msgs": [m.hex() for m in ms],
        "sig": dagg.hex(), "ok": ok, "note": note,
      })  # fmt: skip
  # Two signers over one message inside a distinct-message aggregate.
  dup = g.must(o.AGGREGATE_SIG, sigs([same[0], same[1], distinct[2]]))
  dup_msgs = [msg, msg, msgs[2]]
  out["distinct"].append({
    "pks": [p.hex() for p in pks[:3]], "msgs": [m.hex() for m in dup_msgs],
    "sig": dup.hex(),
    "ok": g.holds(
      o.VERIFY_AGGREGATED, o.Sig(dup), pk_list(pks[:3]), o.hashes(dup_msgs)
    ),
    "note": "a repeated message",
  })  # fmt: skip
  # A key and its negation sum to the identity.
  neg = flip_sign(pks[0], g.legacy)
  out["pk"].append(
    {
      "pks": [pks[0].hex(), neg.hex()],
      "agg": g.obj(o.AGGREGATE_PK, pk_list([pks[0], neg])),
    }
  )
  for i in range(1, 4):
    agg = g.must(o.AGGREGATE_SIG, sigs(same[: i + 1]))
    out["sub"].append({
      "sig": agg.hex(), "other": same[i].hex(),
      "out": g.obj(o.SUB_SIG, o.Sig(agg), o.Sig(same[i])),
    })  # fmt: skip
  return out


def secure_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "secure", i) for i in range(7)]
  pks = [g.pk(sk) for sk in keys]
  msg = h("secure msg")
  signed = [g.sign(sk, msg) for sk in keys]
  agg_rows, verify = [], []

  def aggregate(ss: list[bytes], ps: list[bytes], note: str) -> bytes | None:
    out = g.obj(o.AGGREGATE_SECURE, sigs(ss), pk_list(ps), o.Raw(msg))
    agg_rows.append({
      "sigs": [s.hex() for s in ss], "pks": [p.hex() for p in ps],
      "msg": msg.hex(), "agg": out, "note": note,
    })  # fmt: skip
    return None if out is None else bytes.fromhex(out)

  def check(sig: bytes, ps: list[bytes], m: bytes, note: str) -> None:
    ok = g.holds(o.VERIFY_SECURE, o.Sig(sig), pk_list(ps), o.Raw(m))
    verify.append({
      "sig": sig.hex(), "pks": [p.hex() for p in ps], "msg": m.hex(),
      "ok": ok, "note": note,
    })  # fmt: skip

  for n in (1, 2, 3, 5, 7):
    agg = aggregate(signed[:n], pks[:n], f"{n} signers")
    if agg is None:
      continue
    check(agg, pks[:n], msg, "signed")
    check(agg, pks[:n][::-1], msg, "keys reversed")
    check(agg, pks[:n], h("secure wrong"), "other message")
    if n > 1:
      check(agg, pks[: n - 1], msg, "a key missing")
      plain = g.must(o.AGGREGATE_SIG, sigs(signed[:n]))
      check(plain, pks[:n], msg, "insecure aggregate")
  twice = aggregate(
    [signed[0], signed[0]], [pks[0], pks[0]], "one signer twice"
  )
  if twice is not None:
    check(twice, [pks[0], pks[0]], msg, "one signer twice")
  rev = aggregate(signed[:3][::-1], pks[:3][::-1], "3 signers reversed")
  if rev is not None:
    check(rev, pks[:3], msg, "aggregated reversed")
  return {"aggregate": agg_rows, "verify": verify}


def threshold_rows(g: Gen, tag: str) -> list[Row]:
  cases = []
  for t in (1, 2, 3, 4):
    n = t + 2
    msk = [sk_of(tag, "msk", t, i) for i in range(t)]
    mpk = [g.pk(sk) for sk in msk]
    ids = [h("id", t, i) for i in range(n)]
    sk_shares = [g.obj(o.SK_SHARE, sks(msk), o.Raw(i)) for i in ids]
    pk_shares = [g.obj(o.PK_SHARE, pk_list(mpk), o.Raw(i)) for i in ids]
    msg = h("threshold msg", t)
    master_sig = g.sign(msk[0], msg)
    sig_shares = [
      g.sign(bytes.fromhex(s), msg) if s else None for s in sk_shares
    ]
    recover = []
    subsets = [list(range(t)), list(range(n - t, n)), list(range(n))]
    subsets += [list(range(t - 1)), [0, *range(t - 1)]]
    for subset in subsets:
      if not subset or any(sig_shares[i] is None for i in subset):
        continue
      shares = [sig_shares[i] or b"" for i in subset]
      sig = g.obj(o.RECOVER_SIG, sigs(shares), o.hashes(ids[i] for i in subset))
      recover.append({
        "subset": subset, "sig": sig,
        "is_master": sig == master_sig.hex(),
      })  # fmt: skip
    cases.append({
      "t": t, "msk": [k.hex() for k in msk], "mpk": [p.hex() for p in mpk],
      "ids": [i.hex() for i in ids], "sk_shares": sk_shares,
      "pk_shares": pk_shares, "msg": msg.hex(), "master_sig": master_sig.hex(),
      "sig_shares": [s.hex() if s else None for s in sig_shares],
      "recover": recover,
    })  # fmt: skip
  return cases


def ies_rows(g: Gen, tag: str) -> Row:
  keys = [sk_of(tag, "ies", i) for i in range(4)]
  pks = [g.pk(sk) for sk in keys]
  layouts = [
    ("one share", [32]),
    ("three shares", [32, 32, 32]),
    ("mixed lengths", [16, 48, 64, 32]),
    ("misaligned", [32, 33]),
    ("empty", [0]),
  ]
  multi, blobs = [], []
  for case, (note, lengths) in enumerate(layouts):
    eph = sk_of(tag, "ies eph", case)
    iv = h("ies iv", tag, case)
    recips = pks[: len(lengths)]
    plains = [h("ies data", case, i, "x") * 3 for i in range(len(lengths))]
    plains = [p[:n] for p, n in zip(plains, lengths, strict=True)]
    ret, enc = g.call(
      o.IES_ENCRYPT, o.Sk(eph), o.Raw(iv), pk_list(recips), o.blobs(plains)
    )
    if ret not in (o.OK, o.REJECT):
      msg = f"IES encrypt returned {ret}"
      raise o.OracleError(msg)
    out = enc.hex() if ret == o.OK else None
    row: Row = {
      "eph_sk": eph.hex(), "iv_seed": iv.hex(),
      "recipients": [p.hex() for p in recips],
      "plaintexts": [p.hex() for p in plains], "out": out, "note": note,
      "decrypt": [],
    }  # fmt: skip
    if out is not None:
      enc = bytes.fromhex(out)
      tries = [(i, keys[i]) for i in range(len(lengths))]
      tries += [(0, keys[-1]), (len(lengths), keys[0])]
      decrypts = []
      for idx, sk in tries:
        ret, plain = g.call(
          o.IES_DECRYPT, o.Raw(o.u32(idx)), o.Sk(sk), o.Raw(o.blob(enc))
        )
        if ret not in (o.OK, o.REJECT):
          msg = f"IES decrypt returned {ret}"
          raise o.OracleError(msg)
        decrypts.append({
          "idx": idx, "sk": sk.hex(),
          "plain": plain.hex() if ret == o.OK else None,
        })  # fmt: skip
      row["decrypt"] = decrypts
      eph_pk = enc[:48]
      for i in range(len(lengths)):
        ct = enc_blob(enc, i)
        one = eph_pk + iv + o.blob(ct)
        ret, plain = g.call(
          o.IES_DECRYPT_BLOB, o.Raw(o.u32(i)), o.Sk(keys[i]), o.Raw(o.blob(one))
        )
        blobs.append({
          "idx": i, "sk": keys[i].hex(), "blob": one.hex(),
          "plain": plain.hex() if ret == o.OK else None,
        })  # fmt: skip
    multi.append(row)
  return {"multi": multi, "blob": blobs}


def enc_blob(enc: bytes, index: int) -> bytes:
  """Blob `index` of a serialized CBLSIESMultiRecipientBlobs."""
  pos = 48 + 32
  count, pos = o.read_compact(enc, pos)
  for i in range(count):
    n, pos = o.read_compact(enc, pos)
    if i == index:
      return enc[pos : pos + n]
    pos += n
  msg = "no such blob"
  raise IndexError(msg)


EXOTIC = (
  "tors_",
  "nonsub_",
  "off_",
)  # bls_wrapper classes off G1/G2's subgroup


def edge_rows(probe: o.Probe, decoded: list[Row]) -> list[Row]:
  """Core's verifications over invalid and exotic operands: objects decoded
  under one scheme, verified under either flag."""
  exotic = {
    kind: [
      bytes.fromhex(str(r["in"]))
      for r in decoded
      if r["kind"] == kind
      and str(r["class"]).startswith(EXOTIC)
      and str(r["eager_legacy"]).startswith("V")
    ][:2]
    for kind in ("pk", "sig")
  }
  zero_pk, zero_sig = bytes(48), bytes(96)
  rows: list[Row] = []
  for decode, legacy in SCHEMES.items():
    g = Gen(probe, legacy)
    keys = [sk_of("edge", decode, i) for i in range(2)]
    pks = [g.pk(sk) for sk in keys]
    msgs = [h("edge msg", i) for i in range(2)]
    sig = g.sign(keys[0], msgs[0])
    agg = g.must(o.AGGREGATE_SIG, sigs([sig, g.sign(keys[1], msgs[1])]))
    same = [g.sign(sk, msgs[0]) for sk in keys]
    sec = g.must(o.AGGREGATE_SECURE, sigs(same), pk_list(pks), o.Raw(msgs[0]))
    # Core aggregates an invalid object's element, infinity, as it verifies.
    zero_sigs, zero_pks = [same[0], zero_sig], [pks[0], zero_pk]
    sec_zero = g.must(
      o.AGGREGATE_SECURE, sigs(zero_sigs), pk_list(zero_pks), o.Raw(msgs[0])
    )
    xpk, xsig = (exotic["pk"], exotic["sig"]) if legacy else ([], [])
    insecure = [(sig, pks[0], "signed"), (zero_sig, pks[0], "invalid sig")]
    insecure += [(sig, zero_pk, "invalid key")]
    insecure += [(sig, x, "exotic key") for x in xpk]
    insecure += [(x, pks[0], "exotic sig") for x in xsig]
    aggregated = [
      (agg, pks, msgs, "signed"),
      (agg, [pks[0], zero_pk], msgs, "an invalid key"),
      (zero_sig, [], [], "invalid sig, no keys"),
      (agg, pks, [msgs[0], msgs[0]], "a message twice"),
    ]
    aggregated += [(agg, [pks[0], x], msgs, "an exotic key") for x in xpk]
    aggregated += [(x, pks, msgs, "exotic sig") for x in xsig]
    secure = [
      (sec, pks, "signed"),
      (sec, [pks[0], zero_pk], "an invalid key"),
      (zero_sig, [zero_pk], "all invalid"),
      (zero_sig, [zero_pk, zero_pk], "all invalid, twice"),
      (sec, [zero_pk], "invalid key"),
      (sec_zero, zero_pks, "signed with an invalid key"),
      (sec_zero, zero_pks[::-1], "signed with an invalid key, reversed"),
    ]
    secure += [(sec, [pks[0], x], "an exotic key") for x in xpk]
    secure += [(x, pks, "exotic sig") for x in xsig]
    for flag, flag_legacy in SCHEMES.items():

      def row(
        op: str,
        s: bytes,
        ps: list[bytes],
        ms: list[bytes],
        ok: bool,
        note: str,
        decode: str = decode,
        flag: str = flag,
      ) -> Row:
        return {
          "op": op,
          "decode": decode,
          "flag": flag,
          "sig": s.hex(),
          "pks": [p.hex() for p in ps],
          "msgs": [m.hex() for m in ms],
          "ok": ok,
          "note": note,
        }

      for s, p, note in insecure:
        ok = probe.holds(
          o.VERIFY, legacy, o.Sig(s), o.Pk(p), o.Raw(msgs[0]), flag=flag_legacy
        )
        rows.append(row("insecure", s, [p], msgs[:1], ok, note))
      for s, ps, ms, note in aggregated:
        ok = probe.holds(
          o.VERIFY_AGGREGATED,
          legacy,
          o.Sig(s),
          pk_list(ps),
          o.hashes(ms),
          flag=flag_legacy,
        )
        rows.append(row("aggregated", s, ps, ms, ok, note))
      for s, ps, note in secure:
        ok = probe.holds(
          o.VERIFY_SECURE,
          legacy,
          o.Sig(s),
          pk_list(ps),
          o.Raw(msgs[0]),
          flag=flag_legacy,
        )
        rows.append(row("secure", s, ps, msgs[:1], ok, note))
  return rows


def decode_rows(probe: o.Probe) -> list[Row]:
  """bls_wrapper's eager inputs, decoded by the oracle eagerly and lazily."""
  # bls_wrapper's generator, loaded by path: it is also named gen. Its
  # directory goes on the path for its own imports.
  sys.path.insert(0, str(WRAPPER_DIR))
  spec = importlib.util.spec_from_file_location(
    "bls_wrapper_gen", WRAPPER_DIR / "gen.py"
  )
  if spec is None or spec.loader is None:
    msg = f"cannot load {WRAPPER_DIR / 'gen.py'}"
    raise o.OracleError(msg)
  wrapper = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(wrapper)

  inputs = wrapper.gen_inputs(random.Random(wrapper.SEED), 3)  # noqa: S311
  kinds = {"pk": o.PK, "sig": o.SIG, "sk": o.SK}
  rows = []
  for kind, entries in inputs.items():
    base = kind.removesuffix("_basic")
    for name, raw in entries:
      row: Row = {"kind": base, "class": name, "in": raw.hex()}
      for scheme, legacy in SCHEMES.items():
        modes = [("eager", o.EAGER)]
        if base != "sk":
          modes.append(("lazy", o.LAZY))
        for mode_name, mode in modes:
          ret, valid, out = probe.decode(kinds[base], mode, legacy, raw)
          row[f"{mode_name}_{scheme}"] = outcome(ret, valid, out)
      rows.append(row)
  return rows


def outcome(ret: int, valid: bool, out: bytes) -> str:
  """T (Core throws), I (invalid, serializes as zeros) or V:<serialization>."""
  if ret == o.E_DECODE:
    return "T"
  if ret != o.OK:
    msg = f"decode returned {ret}"
    raise o.OracleError(msg)
  return f"V:{out.hex()}" if valid else "I"


def per_scheme(probe: o.Probe, build: Callable[[Gen, str], object]) -> Row:
  return {s: build(Gen(probe, legacy), s) for s, legacy in SCHEMES.items()}


def render(value: object, depth: int = 0) -> str:
  """JSON with each record of a list of records on a line of its own."""
  pad = "  " * (depth + 1)
  if isinstance(value, dict) and value:
    items = [
      f"{pad}{json.dumps(k)}: {render(v, depth + 1)}" for k, v in value.items()
    ]
    return "{\n" + ",\n".join(items) + "\n" + "  " * depth + "}"
  if isinstance(value, list) and value and isinstance(value[0], dict):
    items = [pad + json.dumps(v) for v in value]
    return "[\n" + ",\n".join(items) + "\n" + "  " * depth + "]"
  return json.dumps(value)


def emit(path: Path, header: str, body: object) -> None:
  path.write_text(f"// {header}\n" + render(body) + "\n")


def main() -> int:
  ap = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  ap.add_argument("--probe", required=True)
  ap.add_argument("--out-dir", type=Path, required=True)
  args = ap.parse_args()

  probe = o.Probe(args.probe)
  core = probe.core_version
  files = {
    "hash_to_g2": per_scheme(probe, lambda g, _: hash_to_g2(g)),
    "sign": per_scheme(probe, sign_rows),
    "aggregate": per_scheme(probe, aggregate_rows),
    "secure": per_scheme(probe, secure_rows),
    "threshold": per_scheme(probe, threshold_rows),
    "ies": per_scheme(probe, ies_rows),
  }
  files["decode"] = {"rows": decode_rows(probe)}
  files["edge"] = {"rows": edge_rows(probe, files["decode"]["rows"])}
  probe.close()
  args.out_dir.mkdir(parents=True, exist_ok=True)
  for name, body in files.items():
    header = f"Dash Core {core} BLS vectors ({name}); see PROVENANCE.md."
    emit(args.out_dir / f"{name}.json5", header, body)
  return 0


if __name__ == "__main__":
  sys.exit(main())
