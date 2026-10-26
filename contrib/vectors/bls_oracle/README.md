# BLS oracle vectors

`pkgs/pkc/corpus/bls_oracle/*.json5` record what Dash Core's own BLS code (`src/bls/` and its bundled dashbls) returns
for signing, verification, aggregation, threshold sharing, IES and a regtest DKG. The inputs are chosen here; every
output, verdict and decode outcome is Core's, read through the consensus oracle's `oracle_bls_exec` (ABI 14), a script
of BLS operations over registers holding Core's objects. `relic.json5` needs ABI 19, which adds element operations,
relic's error code after each operation and the log of relic calls Core made; `arith.json5` needs ABI 26's pair and
in-place flags. `PROVENANCE.md` in the corpus directory names the Core commit, the archive, the command and the sha256
of each file; `pkgs/pkc/tests/bls_oracle.rs` checks every file against `dash_pkc::bls::core` and the typed API, and
fails when a file and `PROVENANCE.md` disagree.

| File | Role |
|---|---|
| `probe.c` | Reads scripts on stdin and prints `oracle_bls_exec`'s status and records |
| `build.sh` | Links `probe.c` against an oracle archive (`libdash_oracle_<pin>.a`) |
| `oracle.py` | The script encoding (`Script`), the record reader and the probe driver (`Probe`) |
| `gen.py` | Seeded inputs for every file but `dkg.json5`, and the JSON5 writer (`--only FILE` writes just that file) |
| `dkg.py` | Extracts a DKG transcript from a functional-test run and has Core check every step |
| `check_upstream.py` | Has Core reproduce every value of the upstream files directly under `pkgs/pkc/corpus/`; writes nothing |

## Regenerating

The archive comes from rust-dashcore's `contrib/node/build-oracle.sh` (the pinned, reproducible build is installed
under `/work/cache/oracle/<commit>/plain` on the build host). Build the probe, then write the generated files from
this directory:

```sh
contrib/vectors/bls_oracle/build.sh <archive> /path/to/probe
python3 gen.py --probe /path/to/probe --out-dir ../../../pkgs/pkc/corpus/bls_oracle
```

Both generators, and the checker below, are standard-library Python 3.

### The DKG transcript

`dkg.json5` comes from a run of Core's `feature_llmq_dkgerrors.py`, which makes members send bad shares, complain,
justify and get excluded. Run it from Core's test tree against a release `dashd` that captures every P2P message and
logs its command line (the operators' regtest secret keys are arguments):

```sh
#!/bin/sh
# build/src/dashd, next to links to the release's dash-cli, dash-tx, dash-util and dash-wallet
echo "$$ $*" >> "$RUN/argv.log"
exec /path/to/release/bin/dashd -capturemessages "$@"
```

```sh
test/functional/feature_llmq_dkgerrors.py --configfile test/config.ini --tmpdir "$RUN/run" --nocleanup
python3 dkg.py --probe /path/to/probe --run "$RUN/run" --argv "$RUN/argv.log" \
  --out ../../../pkgs/pkc/corpus/bls_oracle/dkg.json5
```

The members' contributions are random, so a new run gives a different transcript; the checks are the same.

After regenerating, update the file's section in `PROVENANCE.md`, including its sha256.

## Checking the upstream files

`bls_aggregate`, `bls_dh`, `bls_hash`, `bls_ies`, `bls_keygen`, `bls_llmq_100`, `bls_secure_aggregate`,
`bls_serialize`, `bls_sign` and `bls_threshold` (`.json5`, directly under `pkgs/pkc/corpus/`) came from upstream
without a generator, and their bytes are kept as they are. `check_upstream.py` has Core reproduce their values instead
of writing them; from this directory:

```sh
python3 check_upstream.py --probe /path/to/probe --corpus-dir ../../../pkgs/pkc/corpus
```

A "chia" section is Core's legacy scheme and an "ietf" section its basic one. The checker prints a line per file with
its values in five classes: reproduced (Core's output, or the checker's copy of the glue Core runs outside its BLS
library, over Core's outputs: sha256d, the uint256 byte order and its serialization layout), verified (randomness the
file does not record, the DKG's coefficients and the operators' keys, so Core's own verification is the check), not
reproduced, not reachable (no op or composition of ops yields it; each such field is listed with the reason) and inputs
(keys, messages, ids and counts the file gives; Core reads the objects among them back byte for byte). `--verbose`
prints every value's check. It exits 0 iff every reachable value reproduces, and refuses a probe that is not the Core
build `PROVENANCE.md` names unless given `--any-core`. The corpus directory's `PROVENANCE.md` gives each file's origin
and result.
