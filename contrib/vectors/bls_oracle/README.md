# BLS oracle vectors

`pkgs/pkc/corpus/bls_oracle/*.json5` record what Dash Core's own BLS code (`src/bls/` and its bundled dashbls) returns
for signing, verification, aggregation, threshold sharing, IES and a regtest DKG. The inputs are chosen here; every
output, verdict and decode outcome is Core's, read through the consensus oracle's `oracle_bls_exec` (ABI 14), a script
of BLS operations over registers holding Core's objects. `PROVENANCE.md` in the corpus directory names the Core commit,
the archive, the command and the sha256 of each file; `pkgs/pkc/tests/bls_oracle.rs` checks every file against
`dash_pkc::bls::core` and the typed API, and fails when a file and `PROVENANCE.md` disagree.

| File | Role |
|---|---|
| `probe.c` | Reads scripts on stdin and prints `oracle_bls_exec`'s status and records |
| `build.sh` | Links `probe.c` against an oracle archive (`libdash_oracle_<pin>.a`) |
| `oracle.py` | The script encoding (`Script`), the record reader and the probe driver (`Probe`) |
| `gen.py` | Seeded inputs for every file but `dkg.json5`, and the JSON5 writer |
| `dkg.py` | Extracts a DKG transcript from a functional-test run and has Core check every step |

## Regenerating

The archive comes from rust-dashcore's `contrib/node/build-oracle.sh` (the pinned, reproducible build is installed
under `/work/cache/oracle/<commit>/plain` on the build host). Build the probe, then write the generated files from
this directory:

```sh
contrib/vectors/bls_oracle/build.sh <archive> /path/to/probe
python3 gen.py --probe /path/to/probe --out-dir ../../../pkgs/pkc/corpus/bls_oracle
```

Both generators are standard-library Python 3.

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
