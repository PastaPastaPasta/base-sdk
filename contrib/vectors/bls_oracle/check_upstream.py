#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Checks the upstream BLS corpus files against Dash Core.

The ten files directly under pkgs/pkc/corpus (bls_aggregate, bls_dh,
bls_hash, bls_ies, bls_keygen, bls_llmq_100, bls_secure_aggregate,
bls_serialize, bls_sign, bls_threshold) came without a generator. This
script has Core's BLS code reproduce every value in them through the
consensus oracle (probe.c) and never writes them. Their "chia" sections
are Core's legacy scheme and their "ietf" sections its basic scheme, as
the crate's BlsScChia and BlsScIetf.

Each value is one of:
  reproduced     Core's output equals it (an op or a composition of ops),
                 or glue Core runs outside its BLS library (sha256d, byte
                 order, Core's serialization layout) over Core's outputs
                 equals it;
  verified       its randomness is not recorded (DKG coefficients, operator
                 keys), so Core's own check of it is what holds;
  input          the file gives it (a key, a message, an id, a count);
                 objects among them are read back by Core, byte for byte,
                 and the rest are checked against the structure Core reads;
  not reachable  no op or composition of ops yields it.
A failed check is "not reproduced". The exit status is 0 iff there are
none.

  check_upstream.py --probe PROBE --corpus-dir pkgs/pkc/corpus [--verbose]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import gen
import oracle as o
from dkg import commitment_hash, display

if TYPE_CHECKING:
  from collections.abc import Callable, Iterator

  Tree = Any

# The sections' schemes (pkgs/pkc/src/bls/schemes.rs: BlsScChia is the
# legacy scheme, BlsScIetf the basic one).
SCHEMES = {"chia": True, "ietf": False}
KINDS = {"sk": o.SK, "pk": o.PK, "sig": o.SIG}
# The ephemeral secret key of bls_ies.json5's images: KeyGen of 0x01 * 32
# (RSEED[1], ies_bytes.rs), as secret_ops.rs's keygen_uses_draft03_variant
# records it. Core derives the images' ephemeral key from it.
IES_BYTES_EPH_SK = bytes.fromhex(
  "6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220"
)
# Their IV seed: RSEED[1], 0x01 * 32, which ies_bytes.rs asserts.
IES_BYTES_SEED = b"\x01" * 32

# The ABI and the Core build PROVENANCE.md names (the oracle shim at 77dbec824):
# its counts hold for that build, so another one is refused without --any-core.
ABI = 28
CORE = "77dbec82427c"

REPRODUCED, GLUE, VERIFIED, INPUT, UNREACHABLE = range(5)
NAMES = {
  REPRODUCED: "reproduced",
  GLUE: "reproduced",
  VERIFIED: "verified",
  INPUT: "input",
  UNREACHABLE: "not reachable",
}


def load_json5(path: Path) -> Tree:
  """The JSON5 the corpora use: line comments and trailing commas."""
  text = re.sub(r"(?m)^\s*//.*$", "", path.read_text())
  return json.loads(re.sub(r",(\s*[}\]])", r"\1", text))


def leaves(value: object, path: str = "") -> Iterator[tuple[str, object]]:
  if isinstance(value, dict):
    for k, v in value.items():
      yield from leaves(v, f"{path}.{k}" if path else k)
  elif isinstance(value, list):
    for i, v in enumerate(value):
      yield from leaves(v, f"{path}[{i}]")
  else:
    yield path, value


def stored(display: str) -> bytes:
  """A uint256 from its GetHex (display) form: the bytes reversed."""
  return bytes.fromhex(display)[::-1]


class Ledger:
  """Every leaf of one file and how it was checked."""

  def __init__(self, name: str, tree: Tree) -> None:
    self.name = name
    self.values = dict(leaves(tree))
    self.marks: dict[str, tuple[int, bool, str]] = {}
    self.failures: list[str] = []
    self.aborted: str | None = None

  def mark(self, path: str, kind: int, ok: bool, note: str) -> None:
    if path not in self.values:
      msg = f"{self.name}: no value at {path}"
      raise KeyError(msg)
    old = self.marks.get(path)
    if old is not None and (old[0] == UNREACHABLE) != (kind == UNREACHABLE):
      msg = f"{self.name}: {path} is both reachable and not"
      raise ValueError(msg)
    if not ok:
      self.failures.append(f"{path}: {note}")
    if old is None or kind < old[0]:
      self.marks[path] = (kind, ok and (old is None or old[1]), note)
    elif not ok:
      self.marks[path] = (old[0], False, old[2])

  def out(
    self, path: str, got: object, how: str, kind: int = REPRODUCED
  ) -> None:
    """The recorded value against Core's (bytes, a verdict or a hex string)."""
    want = self.values.get(path)
    have = got.hex() if isinstance(got, bytes) else got
    ok = want == have
    self.mark(path, kind, ok, how if ok else f"{how}: Core gives {have}")

  def glue(self, path: str, got: object, how: str) -> None:
    self.out(path, got, how, GLUE)

  def verified(self, path: str, ok: bool, how: str) -> None:
    self.mark(path, VERIFIED, ok, how if ok else f"{how} fails")

  def given(self, path: str, ok: bool = True, how: str = "input") -> None:
    self.mark(path, INPUT, ok, how if ok else f"{how} fails")

  def unreachable(
    self, path: str, reason: str, ok: bool = True, rest: str = ""
  ) -> None:
    """A value no op yields; `rest` names a check of the parts Core does
    fix, which `ok` says held."""
    note = f"{reason}; {rest}" if rest else reason
    self.mark(path, UNREACHABLE, ok, note if ok else f"{rest}: they differ")

  def abort(self, why: str) -> None:
    """The file stops: a value Core refuses, or values with no check."""
    self.aborted = why

  def finish(self) -> None:
    missing = sorted(set(self.values) - set(self.marks))
    if missing:
      more = ", ..." if len(missing) > 5 else ""
      listed = ", ".join(missing[:5])
      self.abort(f"no check for {len(missing)} values: {listed}{more}")


class Core:
  """The probe, with the compositions the files need."""

  def __init__(self, probe: o.Probe) -> None:
    self.p = probe

  def g(self, legacy: bool) -> gen.Gen:
    return gen.Gen(self.p, legacy)

  def read(self, kind: str, legacy: bool, raw: bytes) -> bool:
    """Core decodes the object as valid and writes the same bytes back."""
    ret, valid, out = self.p.decode(KINDS[kind], o.EAGER, legacy, raw)
    return ret == o.OK and valid and out == raw

  def script(self, s: o.Script) -> list[tuple[int, bytes]]:
    records = self.p.run(s)
    if any(status != o.OK for status, _ in records):
      msg = f"a step returned {[status for status, _ in records]}"
      raise o.OracleError(msg)
    return records

  def reser(self, obj: o.Obj, legacy: bool, flag: bool) -> bytes:
    """The object decoded under one scheme, serialized under the other."""
    return self.p.must(o.SER, legacy, obj, flag=flag)

  def hash_ser(self, msg: bytes, legacy: bool, flag: bool) -> bytes:
    """The scheme's hash to G2, serialized under `flag`."""
    s = o.Script(legacy)
    s.emit(o.HASH_TO_G2, msg)
    s.emit(o.SER, bytes([s.regs - 1]), flag)
    return self.script(s)[-1][1]

  def share_matches(
    self, legacy: bool, sk: bytes, vvec: list[bytes], ident: bytes
  ) -> bool:
    """Core's contribution check: GetPublicKey(share) ==
    PublicKeyShare(vvec, id), by the wrapper's operator==."""
    s = o.Script(legacy)
    s.emit(o.PUBLIC_KEY, s.operand(o.Sk(sk)))
    pk = s.regs - 1
    s.emit(o.PK_SHARE, s.operand(gen.pk_list(vvec)) + ident)
    s.emit(o.EQ, bytes([pk, s.regs - 1]))
    return self.script(s)[-1][1] == b"\x01"


def hexes(items: object) -> list[bytes]:
  return [bytes.fromhex(str(x)) for x in items]


class Witnesses:
  """Secret keys found in the files, by the public key Core derives from
  them under each scheme: a recorded key with a witness has its
  signatures re-signed by Core rather than only verified."""

  def __init__(self, core: Core, trees: dict[str, Tree]) -> None:
    sks: set[bytes] = set()
    for tree in trees.values():
      for path, value in leaves(tree):
        field = re.sub(r"\[\d+\]", "", path).rsplit(".", 1)[-1]
        if field in ("sk", "sks", "master_sks", "eph_sk", "sk_share"):
          sks.add(bytes.fromhex(str(value)))
    self.by_pk: dict[tuple[bool, bytes], bytes] = {}
    for sk in sorted(sks):
      for legacy in (True, False):
        ret, pk = core.g(legacy).call(o.PUBLIC_KEY, o.Sk(sk))
        # A key Core refuses witnesses nothing; its own file reports it.
        if ret == o.OK:
          self.by_pk[(legacy, pk)] = sk

  def get(self, legacy: bool, pk: bytes) -> bytes | None:
    return self.by_pk.get((legacy, pk))


def check_keygen(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    for i, v in enumerate(tree[sec]["derive_pk"]):
      at = f"{sec}.derive_pk[{i}]"
      sk = bytes.fromhex(v["sk"])
      led.given(f"{at}.sk", c.read("sk", legacy, sk), "Core reads the key")
      led.out(f"{at}.pk", g.pk(sk), "GetPublicKey")


def check_sign(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    for i, v in enumerate(tree[sec]["sign"]):
      at = f"{sec}.sign[{i}]"
      sk, msg = bytes.fromhex(v["sk"]), bytes.fromhex(v["msg"])
      led.given(f"{at}.sk", c.read("sk", legacy, sk), "Core reads the key")
      led.given(f"{at}.msg")
      led.out(f"{at}.sig", g.sign(sk, msg), "Sign")


def check_serialize(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  """chia.X[i] and ietf.X[i] are one point under the two schemes."""
  for kind, cls in (("pk", o.Pk), ("sig", o.Sig)):
    pairs = zip(tree["chia"][kind], tree["ietf"][kind], strict=True)
    for i, (legacy_hex, basic_hex) in enumerate(pairs):
      for sec, raw, other in (
        ("chia", legacy_hex, "ietf"),
        ("ietf", basic_hex, "chia"),
      ):
        legacy = SCHEMES[sec]
        at = f"{sec}.{kind}[{i}]"
        data = bytes.fromhex(raw)
        reads = c.read(kind, legacy, data)
        led.out(at, data if reads else b"", "Core reads it and writes it back")
        if not reads:
          continue
        led.out(
          f"{other}.{kind}[{i}]",
          c.reser(cls(data), legacy, not legacy),
          f"{at} decoded under its scheme, serialized under the other",
        )


def check_hash(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  for i, v in enumerate(tree["chia"]):
    at = f"chia[{i}]"
    msg = bytes.fromhex(v["msg"])
    led.given(f"{at}.msg")
    led.out(
      f"{at}.hash_to_g2_legacy",
      c.g(True).must(o.HASH_TO_G2, o.Raw(msg)),
      "the legacy hash to G2",
    )
    led.out(
      f"{at}.hash_to_g2_uncomp",
      c.hash_ser(msg, True, False),
      "the legacy hash to G2, serialized under the basic scheme",
    )
    for t in ("t00", "t01", "t10", "t11"):
      led.unreachable(
        f"{at}.{t}_hash",
        "an intermediate of dashbls' legacy hash to G2 (SHA-256 of msg, a"
        " tag and a counter); Core exposes only the point",
      )
      led.unreachable(
        f"{at}.{t}_fp",
        "an intermediate of dashbls' legacy hash to G2 (the field element"
        " reduced from it); Core exposes only the point",
      )


def check_aggregate(c: Core, led: Ledger, tree: Tree, w: Witnesses) -> None:
  for i, v in enumerate(tree["base"]["sk"]):
    at = f"base.sk[{i}]"
    keys = hexes(v["sks"])
    for j, sk in enumerate(keys):
      ok = c.read("sk", True, sk) and c.read("sk", False, sk)
      led.given(f"{at}.sks[{j}]", ok, "Core reads the key")
    for legacy in (True, False):
      led.out(
        f"{at}.agg_sk",
        c.g(legacy).must(o.AGGREGATE_SK, gen.sks(keys)),
        f"AggregateInsecure of the keys ({'legacy' if legacy else 'basic'})",
      )
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    for i, v in enumerate(tree[sec]["pk"]):
      pks = hexes(v["pks"])
      for j, pk in enumerate(pks):
        led.given(
          f"{sec}.pk[{i}].pks[{j}]",
          c.read("pk", legacy, pk),
          "Core reads the key",
        )
      led.out(
        f"{sec}.pk[{i}].agg_pk",
        g.must(o.AGGREGATE_PK, gen.pk_list(pks)),
        "AggregateInsecure of the keys",
      )
    for i, v in enumerate(tree[sec]["sig"]):
      sigs = hexes(v["sigs"])
      for j, sig in enumerate(sigs):
        led.given(
          f"{sec}.sig[{i}].sigs[{j}]",
          c.read("sig", legacy, sig),
          "Core reads the signature",
        )
      led.out(
        f"{sec}.sig[{i}].agg_sig",
        g.must(o.AGGREGATE_SIG, gen.sigs(sigs)),
        "AggregateInsecure of the signatures",
      )
    for i, v in enumerate(tree[sec]["verify"]):
      at = f"{sec}.verify[{i}]"
      pks, msgs = hexes(v["pks"]), hexes(v["msgs"])
      agg = bytes.fromhex(v["agg_sig"])
      for j, pk in enumerate(pks):
        led.given(
          f"{at}.pks[{j}]", c.read("pk", legacy, pk), "Core reads the key"
        )
      for j in range(len(msgs)):
        led.given(f"{at}.msgs[{j}]")
      signers = [w.get(legacy, pk) for pk in pks]
      if None not in signers:
        signed = [g.sign(sk, m) for sk, m in zip(signers, msgs, strict=True)]
        led.out(
          f"{at}.agg_sig",
          g.must(o.AGGREGATE_SIG, gen.sigs(signed)),
          "AggregateInsecure of Sign(msgs[j]) by the keys' witnesses",
        )
      accepted = g.holds(
        o.VERIFY_AGGREGATED, o.Sig(agg), gen.pk_list(pks), o.hashes(msgs)
      )
      led.out(f"{at}.accepted", accepted, "VerifyInsecureAggregated")
      if None in signers:
        # No secret key to re-sign with: Core's verdict is the check, and
        # an aggregate Core refuses cannot be checked at all.
        led.verified(
          f"{at}.agg_sig",
          v["accepted"] and accepted,
          "VerifyInsecureAggregated (a key has no witness)",
        )


def check_secure(c: Core, led: Ledger, tree: Tree, w: Witnesses) -> None:
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    for i, v in enumerate(tree[sec]["verify"]):
      at = f"{sec}.verify[{i}]"
      msg = bytes.fromhex(v["msg"])
      pks, sigs = hexes(v["pks"]), hexes(v["sigs"])
      led.given(f"{at}.msg")
      for j, (pk, sig) in enumerate(zip(pks, sigs, strict=True)):
        led.given(
          f"{at}.pks[{j}]", c.read("pk", legacy, pk), "Core reads the key"
        )
        sk = w.get(legacy, pk)
        if sk is not None:
          led.out(
            f"{at}.sigs[{j}]", g.sign(sk, msg), "Sign by the key's witness"
          )
        else:
          led.verified(
            f"{at}.sigs[{j}]", g.verify(pk, sig, msg), "VerifyInsecure"
          )
      agg = g.must(
        o.AGGREGATE_SECURE, gen.sigs(sigs), gen.pk_list(pks), o.Raw(msg)
      )
      led.out(f"{at}.agg_sig_secure", agg, "AggregateSecure")
      led.verified(
        f"{at}.agg_sig_secure",
        g.holds(o.VERIFY_SECURE, o.Sig(agg), gen.pk_list(pks), o.Raw(msg)),
        "VerifySecureAggregated",
      )


def check_dh(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    for i, v in enumerate(tree[sec]["dh"]):
      at = f"{sec}.dh[{i}]"
      sk, peer = bytes.fromhex(v["sk"]), bytes.fromhex(v["peer_pk"])
      led.given(f"{at}.sk", c.read("sk", legacy, sk), "Core reads the key")
      led.given(
        f"{at}.peer_pk", c.read("pk", legacy, peer), "Core reads the key"
      )
      led.out(
        f"{at}.shared", g.must(o.DH, o.Sk(sk), o.Pk(peer)), "DHKeyExchange"
      )
    check_dh_ies(c, led, tree[sec]["ies"], sec, legacy)


def check_dh_ies(c: Core, led: Ledger, v: Tree, sec: str, legacy: bool) -> None:
  """The recorded ephemeral key and IV seed are the randomness InitEncrypt
  draws; the oracle takes both, so Core encrypts with them."""
  g = c.g(legacy)
  at = f"{sec}.ies"
  eph, seed = bytes.fromhex(str(v["eph_sk"])), bytes.fromhex(str(v["iv_seed"]))
  eph_pk = bytes.fromhex(str(v["eph_pk"]))
  led.given(f"{at}.eph_sk", c.read("sk", legacy, eph), "Core reads the key")
  led.out(f"{at}.eph_pk", g.pk(eph), "GetPublicKey")
  recips = v["recipients"]
  keys = [bytes.fromhex(r["sk"]) for r in recips]
  pks = [bytes.fromhex(r["pk"]) for r in recips]
  plains = [bytes.fromhex(r["plaintext"]) for r in recips]
  cts = [bytes.fromhex(r["ciphertext"]) for r in recips]
  enc = g.must(
    o.IES_ENCRYPT, o.Sk(eph), o.Raw(seed), gen.pk_list(pks), o.blobs(plains)
  )
  # Core's container: the ephemeral key, the seed, then the blobs.
  led.out(f"{at}.eph_pk", enc[:48], "the ephemeral key of Core's container")
  led.out(f"{at}.iv_seed", enc[48:80], "the seed of Core's container", INPUT)
  for i, (sk, pk, plain) in enumerate(zip(keys, pks, plains, strict=True)):
    r = f"{at}.recipients[{i}]"
    led.given(f"{r}.sk", c.read("sk", legacy, sk), "Core reads the key")
    led.out(f"{r}.pk", g.pk(sk), "GetPublicKey")
    dh = g.must(o.DH, o.Sk(eph), o.Pk(pk))
    led.out(f"{r}.shared", dh, "DHKeyExchange(eph_sk, pk)")
    dh = g.must(o.DH, o.Sk(sk), o.Pk(eph_pk))
    led.out(f"{r}.shared", dh, "DHKeyExchange(sk, eph_pk)")
    led.out(
      f"{r}.ciphertext",
      gen.enc_blob(enc, i),
      "blob i of Core's encryption with the recorded ephemeral key and seed",
    )
    ret, out = g.call(
      o.IES_DECRYPT, o.Raw(o.u32(i)), o.Sk(sk), o.Raw(o.blob(enc))
    )
    led.out(
      f"{r}.plaintext",
      out if ret == o.OK else b"",
      "Core decrypts blob i with the recipient's key",
      INPUT,
    )
    # GetIV(i) (bls_ies.cpp): the seed through ::SerializeHash, sha256d,
    # i times; AES takes its first 16 bytes.
    iv = seed
    for _ in range(i):
      iv = o.sha256d(iv)
    led.glue(f"{r}.iv", iv[:16], "the seed through sha256d i times")
    # At index 0 Core takes the seed's first 16 bytes as the IV, so a blob
    # seeded with the recorded IV decrypts the recorded ciphertext to the
    # recorded plaintext only if it is the IV Core encrypted with (CBC's
    # first block is the IV xor the block's decryption).
    one = eph_pk + bytes.fromhex(recips[i]["iv"]) + bytes(16)
    ret, out = g.call(
      o.IES_DECRYPT_BLOB,
      o.Raw(o.u32(0)),
      o.Sk(sk),
      o.Raw(o.blob(one + o.blob(cts[i]))),
    )
    led.mark(
      f"{r}.iv",
      GLUE,
      ret == o.OK and out == plain,
      "Core decrypts the ciphertext under it to the plaintext",
    )


def blob_lengths(image: bytes, multi: bool) -> list[int] | None:
  """The lengths of an image's blobs, read by Core's layout (the ephemeral
  key, the seed, then one CompactSize-prefixed blob or a CompactSize
  count of them), or None if the image does not end with the last blob."""
  pos, count = 80, 1
  if multi:
    count, pos = o.read_compact(image, pos)
  lens = []
  for _ in range(count):
    n, pos = o.read_compact(image, pos)
    lens.append(n)
    pos += n
  return lens if pos == len(image) else None


def check_ies(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  """Images of CBLSIESEncryptedBlob and CBLSIESMultiRecipientBlobs under
  a fixed ephemeral secret key and IV seed (IES_BYTES_EPH_SK and
  IES_BYTES_SEED). Core writes an image when it encrypts, with that key
  and seed, the plaintext it decrypts from the image (a recipient key: the
  ephemeral key itself). The blob bytes are filler, which that round trip
  keeps whatever it is: Core fixes the ephemeral key, the seed and the
  layout, not the filler.

  Core encrypts only lengths that are multiples of 16. For an image
  holding another length the filler is not reachable, but Core still
  writes the container around a blob it refuses, zero-filled: the image
  with its filler zeroed must be Core's ephemeral key, seed, blob count
  and length prefixes."""
  eph, seed = IES_BYTES_EPH_SK, IES_BYTES_SEED
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    eph_pk = g.pk(eph)

    def encrypt(plains: list[bytes]) -> tuple[int, bytes]:
      n = len(plains)
      pks = gen.pk_list([eph_pk] * n)  # noqa: B023 (used at once)
      return g.call(  # noqa: B023
        o.IES_ENCRYPT, o.Sk(eph), o.Raw(seed), pks, o.blobs(plains)
      )

    for part in ("blob", "multi"):
      multi = part == "multi"
      for i, v in enumerate(tree[sec][part]):
        at = f"{sec}.{part}[{i}]"
        image = bytes.fromhex(v["image"])
        lens = v["blob_lens"] if multi else [v["data_len"]]
        layout = blob_lengths(image, multi) == lens
        names = (
          [f"{at}.blob_lens[{j}]" for j in range(len(lens))]
          if multi
          else [f"{at}.data_len"]
        )
        for name in names:
          led.given(name, layout, "the image's layout holds these lengths")
        op = o.IES_DECRYPT if multi else o.IES_DECRYPT_BLOB
        whole = g.call(op, o.Raw(o.u32(0)), o.Sk(eph), o.Raw(o.blob(image)))
        longer = g.call(
          op, o.Raw(o.u32(0)), o.Sk(eph), o.Raw(o.blob(image + b"\0"))
        )
        reads = whole[0] in (o.OK, o.REJECT) and longer[0] < 0
        if not reads or not layout:
          led.out(f"{at}.image", b"", "Core reads the image and its layout")
          continue
        if any(n % 16 for n in lens):
          led.unreachable(
            f"{at}.image",
            "the filler of a blob whose length is not a multiple of 16: Core's"
            " IES encryption (AES-256-CBC, no padding) refuses that length,"
            " so no op writes it",
            zeroed(image, multi) == refused(encrypt, lens, multi),
            "its ephemeral key, seed, blob count and length prefixes checked"
            " against the container Core writes around zero-filled blobs of"
            " its lengths",
          )
          continue
        plains = []
        for j in range(len(lens)):
          ret, plain = g.call(
            op, o.Raw(o.u32(j)), o.Sk(eph), o.Raw(o.blob(image))
          )
          plains.append(plain if ret == o.OK else b"")
        ret, enc = encrypt(plains)
        if not multi:
          enc = enc[:80] + enc[81:]  # the blob's layout: no blob count
        led.out(
          f"{at}.image",
          enc if ret == o.OK else b"",
          "Core's encryption, under the fixed ephemeral key and seed, of the"
          " plaintext it decrypts from the image",
        )


def zeroed(image: bytes, multi: bool) -> bytes:
  """The image with every blob's filler zeroed (its layout already read)."""
  out, pos, count = bytearray(image), 80, 1
  if multi:
    count, pos = o.read_compact(image, pos)
  for _ in range(count):
    n, pos = o.read_compact(image, pos)
    out[pos : pos + n] = bytes(n)
    pos += n
  return bytes(out)


def refused(
  encrypt: Callable[[list[bytes]], tuple[int, bytes]],
  lens: list[int],
  multi: bool,
) -> bytes | None:
  """Core's container around blobs of these lengths, filler zeroed: the
  ephemeral key, seed and blob count Core writes when it refuses
  zero-filled blobs of all of them, then each blob's length prefix from an
  encryption of that blob alone (the blobs after a refused one come out
  empty). None if Core does not refuse."""
  ret, enc = encrypt([bytes(n) for n in lens])
  if ret != o.REJECT:
    return None
  out = enc[:80]
  if multi:
    out += o.compact(o.read_compact(enc, 80)[0])
  for n in lens:
    ret, enc = encrypt([bytes(n)])
    if ret not in (o.OK, o.REJECT) or enc[:80] != out[:80]:
      return None
    size, pos = o.read_compact(enc, 81)
    out += enc[81:pos] + bytes(size)
  return out


def check_threshold(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    at = f"{sec}.recover_sig"
    inp = tree[sec]["recover_sig"]["inputs"]
    msk, msg = hexes(inp["master_sks"]), bytes.fromhex(inp["msg"])
    led.given(f"{at}.inputs.msg")
    led.given(
      f"{at}.inputs.t", inp["t"] == len(msk), "t is the coefficient count"
    )
    for j, sk in enumerate(msk):
      led.given(
        f"{at}.inputs.master_sks[{j}]",
        c.read("sk", legacy, sk),
        "Core reads the key",
      )
    for k, out in enumerate(tree[sec]["recover_sig"]["outputs"]):
      o_at = f"{at}.outputs[{k}]"
      n = len(out["sk_shares"])
      led.given(f"{at}.inputs.n", inp["n"] == n, "n is the share count")
      # Share i has id i + 1, a uint256 whose stored bytes read big-endian
      # are i + 1 (tests.rs make_id).
      ids = [(i + 1).to_bytes(32, "big") for i in range(n)]
      shares = [g.must(o.SK_SHARE, gen.sks(msk), o.Raw(ident)) for ident in ids]
      sig_shares = [g.sign(s, msg) for s in shares]
      for i in range(n):
        led.out(
          f"{o_at}.sk_shares[{i}]", shares[i], "SecretKeyShare(master_sks, id)"
        )
        led.out(
          f"{o_at}.sig_shares[{i}]", sig_shares[i], "Sign by sk_shares[i]"
        )
      picked = out["recover_ids"]
      for j, ident in enumerate(picked):
        led.given(
          f"{o_at}.recover_ids[{j}]",
          1 <= ident <= n and len(picked) == inp["t"],
          "an id among the shares'",
        )
      recorded = hexes(out["sig_shares"])
      led.out(
        f"{o_at}.recovered_sig",
        g.must(
          o.RECOVER_SIG,
          gen.sigs([recorded[i - 1] for i in picked]),
          o.hashes(ids[i - 1] for i in picked),
        ),
        "Recover of the recorded shares at recover_ids",
      )
      led.out(f"{o_at}.full_sig", g.sign(msk[0], msg), "Sign by master_sks[0]")


def check_llmq(c: Core, led: Ledger, tree: Tree, _: Witnesses) -> None:
  """A regtest DKG of LLMQ type 100 as Core runs it (src/active/
  dkgsession.cpp): each member's contribution, every member's check of
  the shares it received, the premature commitments (quorumSig =
  skShare.Sign(commitmentHash), sig by the operator key) and the final
  commitment (membersSig = AggregateSecure, quorumSig = Recover). Ids and
  hashes are written as uint256::GetHex prints them, the stored bytes
  reversed."""
  for sec, legacy in SCHEMES.items():
    g = c.g(legacy)
    d = tree[sec]
    inp, contribs = d["inputs"], d["contribute"]
    fin, commits = d["finalize"], d["commit"]
    member_ids = inp["member_ids"]
    ids = [stored(m) for m in member_ids]
    qhash = str(fin["quorum_hash"])
    led.given(
      f"{sec}.inputs.llmq_type",
      inp["llmq_type"] == fin["llmq_type"],
      "the quorum's type",
    )
    led.given(
      f"{sec}.inputs.n",
      inp["n"] == len(member_ids) == len(contribs),
      "the member count",
    )
    led.given(
      f"{sec}.inputs.t",
      all(len(x["vvec"]) == inp["t"] for x in contribs),
      "the vvec length",
    )
    for i in range(len(member_ids)):
      led.given(f"{sec}.inputs.member_ids[{i}]")
    vvecs = [hexes(x["vvec"]) for x in contribs]
    for ci, x in enumerate(contribs):
      at = f"{sec}.contribute[{ci}]"
      header(led, at, x, ci, qhash, inp["llmq_type"])
      led.given(
        f"{at}.member_id", x["member_id"] == member_ids[ci], "the member's id"
      )
      for k, pk in enumerate(vvecs[ci]):
        led.given(
          f"{at}.vvec[{k}]", c.read("pk", legacy, pk), "Core reads the key"
        )
      for j, share in enumerate(hexes(x["sk_shares"])):
        led.verified(
          f"{at}.sk_shares[{j}]",
          c.read("sk", legacy, share)
          and c.share_matches(legacy, share, vvecs[ci], ids[j]),
          "GetPublicKey(share) == PublicKeyShare(vvec, member_ids[j])",
        )
    for mi, v in enumerate(d["verify"]):
      at = f"{sec}.verify[{mi}]"
      led.given(f"{at}.member_idx", v["member_idx"] == mi, "the member's index")
      for ci, (vv, share) in enumerate(
        zip(v["received_vvecs"], v["received_sk_contributions"], strict=True)
      ):
        for k, pk in enumerate(vv):
          led.given(
            f"{at}.received_vvecs[{ci}][{k}]",
            pk == contribs[ci]["vvec"][k],
            "contribute[c].vvec",
          )
        led.given(
          f"{at}.received_sk_contributions[{ci}]",
          share == contribs[ci]["sk_shares"][mi],
          "contribute[c].sk_shares[m]",
        )
        led.out(
          f"{at}.verification_results[{ci}]",
          c.share_matches(legacy, bytes.fromhex(share), hexes(vv), ids[mi]),
          "GetPublicKey(share) == PublicKeyShare(vvec, member_ids[m])",
        )
    signers = [member_ids.index(s) for s in fin["signer_ids"]]
    member_pks = hexes(fin["member_pks"])
    sk_shares: list[bytes] = []
    commitments: list[bytes] = []
    for mi, x in enumerate(commits):
      at = f"{sec}.commit[{mi}]"
      header(led, at, x, mi, qhash, inp["llmq_type"])
      valid = x["valid_members"]
      for ci, flag in enumerate(valid):
        led.given(
          f"{at}.valid_members[{ci}]",
          flag == d["verify"][mi]["verification_results"][ci],
          "the member's verdict",
        )
      take = [ci for ci, flag in enumerate(valid) if flag]
      qvvec = [
        g.must(o.AGGREGATE_PK, gen.pk_list([vvecs[ci][k] for ci in take]))
        for k in range(inp["t"])
      ]
      for k, pk in enumerate(qvvec):
        led.out(
          f"{at}.quorum_vvec[{k}]",
          pk,
          "AggregateInsecure of the vvecs' coefficient k",
        )
      led.out(f"{at}.quorum_public_key", qvvec[0], "quorum_vvec[0]")
      share = g.must(
        o.AGGREGATE_SK,
        gen.sks([bytes.fromhex(contribs[ci]["sk_shares"][mi]) for ci in take]),
      )
      sk_shares.append(share)
      led.out(
        f"{at}.sk_share", share, "AggregateInsecure of the received shares"
      )
      # ::SerializeHash(vvec) and BuildCommitmentHash (commitment.cpp):
      # sha256d over Core's serialization of Core's outputs.
      vvec_hash = o.sha256d(o.vec(qvvec))
      led.glue(
        f"{at}.quorum_vvec_hash",
        display(vvec_hash),
        "sha256d of the quorum vvec",
      )
      commitment = commitment_hash(
        inp["llmq_type"], stored(qhash), valid, qvvec[0], vvec_hash
      )
      commitments.append(commitment)
      led.glue(
        f"{at}.commitment_hash", display(commitment), "BuildCommitmentHash"
      )
      led.out(
        f"{at}.quorum_sig_share",
        g.sign(share, commitment),
        "skShare.Sign(commitmentHash)",
      )
      pos = signers.index(mi)
      led.verified(
        f"{at}.member_sig",
        x["member_sig"] == fin["member_sigs"][pos]
        and g.verify(
          member_pks[pos], bytes.fromhex(x["member_sig"]), commitment
        ),
        "VerifyInsecure of commitmentHash by the operator key (member_pks)",
      )
    ch = commitments[0]
    at = f"{sec}.finalize"
    led.given(f"{at}.quorum_hash")
    led.given(f"{at}.llmq_type")
    for i, mi in enumerate(signers):
      led.given(
        f"{at}.signer_ids[{i}]", signers.count(mi) == 1, "a member's id"
      )
      led.out(
        f"{at}.threshold_sigs[{i}]",
        g.sign(sk_shares[mi], ch),
        "skShare.Sign(commitmentHash) of the signer",
      )
      led.given(
        f"{at}.member_pks[{i}]",
        c.read("pk", legacy, member_pks[i]),
        "Core reads the key (an operator's)",
      )
      led.verified(
        f"{at}.member_sigs[{i}]",
        g.verify(member_pks[i], bytes.fromhex(fin["member_sigs"][i]), ch),
        "VerifyInsecure by member_pks[i] of commitmentHash",
      )
    tsigs = hexes(fin["threshold_sigs"])
    rec = g.must(
      o.RECOVER_SIG, gen.sigs(tsigs), o.hashes(ids[mi] for mi in signers)
    )
    led.out(
      f"{at}.recovered_quorum_sig", rec, "Recover(threshold_sigs, signer_ids)"
    )
    qpk = bytes.fromhex(str(commits[0]["quorum_public_key"]))
    led.verified(
      f"{at}.recovered_quorum_sig",
      g.verify(qpk, rec, ch),
      "VerifyInsecure by the quorum key",
    )
    msigs = hexes(fin["member_sigs"])
    agg = g.must(
      o.AGGREGATE_SECURE, gen.sigs(msigs), gen.pk_list(member_pks), o.Raw(ch)
    )
    led.out(
      f"{at}.aggregated_members_sig",
      agg,
      "AggregateSecure(member_sigs, member_pks)",
    )
    led.verified(
      f"{at}.aggregated_members_sig",
      g.holds(o.VERIFY_SECURE, o.Sig(agg), gen.pk_list(member_pks), o.Raw(ch)),
      "VerifySecureAggregated",
    )


def header(
  led: Ledger, at: str, x: dict, idx: int, qhash: str, llmq: int
) -> None:
  led.given(f"{at}.quorum_hash", x["quorum_hash"] == qhash, "the quorum's hash")
  led.given(f"{at}.llmq_type", x["llmq_type"] == llmq, "the quorum's type")
  led.given(f"{at}.member_idx", x["member_idx"] == idx, "the member's index")


CHECKS: dict[str, Callable[[Core, Ledger, Tree, Witnesses], None]] = {
  "bls_aggregate": check_aggregate,
  "bls_dh": check_dh,
  "bls_hash": check_hash,
  "bls_ies": check_ies,
  "bls_keygen": check_keygen,
  "bls_llmq_100": check_llmq,
  "bls_secure_aggregate": check_secure,
  "bls_serialize": check_serialize,
  "bls_sign": check_sign,
  "bls_threshold": check_threshold,
}


def report(led: Ledger, verbose: bool) -> None:
  kinds = [kind for kind, _, _ in led.marks.values()]
  failed = sum(not ok for _, ok, _ in led.marks.values())
  failed += led.aborted is not None
  counts = {
    k: sum(x == k and ok for x, ok, _ in led.marks.values()) for k in NAMES
  }
  print(
    f"{led.name}.json5: {len(kinds)} values checked: "
    f"{counts[REPRODUCED] + counts[GLUE]} reproduced"
    f" ({counts[GLUE]} by glue), {counts[VERIFIED]} verified,"
    f" {failed} not reproduced, {counts[UNREACHABLE]} not reachable,"
    f" {counts[INPUT]} inputs"
  )
  fields: dict[str, set[str]] = {}
  for path, (kind, ok, note) in led.marks.items():
    field = re.sub(r"\[\d+\]", "[*]", path)
    if kind == UNREACHABLE:
      fields.setdefault(field, set()).add(note)
    elif verbose:
      print(f"  {path}: {NAMES[kind] if ok else 'not reproduced'}, {note}")
  for field, notes in sorted(fields.items()):
    print(f"  not reachable: {field}: {'; '.join(sorted(notes))}")
  for failure in led.failures:
    print(f"  NOT REPRODUCED: {failure}")
  if led.aborted is not None:
    print(f"  NOT REPRODUCED: {led.aborted}")


def main() -> int:
  ap = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
  )
  ap.add_argument("--probe", required=True)
  ap.add_argument("--corpus-dir", type=Path, required=True)
  ap.add_argument("--verbose", action="store_true", help="every value's check")
  ap.add_argument(
    "--any-core",
    action="store_true",
    help=f"run against a Core build other than {CORE}",
  )
  args = ap.parse_args()

  probe = o.Probe(args.probe)
  print(f"Dash Core {probe.core_version}, oracle ABI {probe.abi}")
  if probe.abi < ABI:
    probe.close()
    ap.error(f"the probe has ABI {probe.abi}; the checks need {ABI} or later")
  if CORE not in probe.core_version and not args.any_core:
    probe.close()
    ap.error(
      f"the probe is not Core {CORE}, which PROVENANCE.md names (--any-core)"
    )
  core = Core(probe)
  trees = {
    name: load_json5(args.corpus_dir / f"{name}.json5") for name in CHECKS
  }
  witnesses = Witnesses(core, trees)
  failed = False
  for name in CHECKS:
    led = Ledger(name, trees[name])
    try:
      CHECKS[name](core, led, trees[name], witnesses)
      led.finish()
    except (o.OracleError, LookupError, ValueError) as e:
      # A value Core refuses (an object it cannot read, say), or one that
      # names no other (an id no member has), stops the file.
      led.abort(f"Core refuses an op ({e}); the file stops there")
    report(led, args.verbose)
    failed |= bool(led.failures or led.aborted)
  probe.close()
  return 1 if failed else 0


if __name__ == "__main__":
  sys.exit(main())
