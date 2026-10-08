# BLS wrapper vectors

`pkgs/pkc/corpus/bls_wrapper.json5` records how Dash Core's BLS wrappers treat byte strings: `CBLSWrapper::Unserialize`
under each scheme flag, `SetBytes` under the basic flag, `CBLSLazyWrapper` operation sequences, and lazy `operator==`.
The inputs are generated here; every outcome comes from Dash Core.

| File | Role |
|---|---|
| `bls12_381.py` | Field and curve arithmetic used to build inputs (subgroup points, on-curve points outside the subgroup, off-curve coordinates, points with `y` in `Fp`) |
| `gen.py` | Seeded input classes, the probe driver and the JSON5 writer |
| `probe.cpp` | Reads inputs on stdin and prints Core's outcome for each, using Core's `bls/bls.h` and its bundled dashbls |
| `build.sh` | Links `probe.cpp` against a Dash Core tree built with autotools on x86_64 (it names Core's SSE4.1, AVX2 and SHA-NI SHA-256 archives) |

## Regenerating

Build Dash Core (any configuration that produces `libbitcoin_consensus.a` and `libdashbls.a`), once per release whose
behaviour the corpus should pin, then build a probe against each tree:

```sh
contrib/vectors/bls_wrapper/build.sh ~/dash-v24.0 /tmp/probe-v24
contrib/vectors/bls_wrapper/build.sh ~/dash-v23.1.8 /tmp/probe-v23
```

From this directory, write the corpus. With several probes, generation stops unless they agree on every input:

```sh
python3 gen.py corpus --probe /tmp/probe-v24 --probe /tmp/probe-v23 \
  --header header.json5 --out ../../../pkgs/pkc/corpus/bls_wrapper.json5
```

`--header` takes the provenance comment kept at the top of the corpus; copy it from the current file and update the
releases it names.

## Larger samples

`gen.py fuzz` draws inputs from the same classes at random and writes one JSON line per input. The ignored test
`generated_differential_sample` in `pkgs/pkc/tests/bls_wrapper.rs` checks such a file:

```sh
python3 gen.py fuzz --probe /tmp/probe-v24 --count 500000 --seed 2026 --out /tmp/bls-sample.jsonl
BLS_WRAPPER_FUZZ=/tmp/bls-sample.jsonl cargo test --release -p dash-pkc --features full --test bls_wrapper \
  -- --ignored generated_differential_sample
```
