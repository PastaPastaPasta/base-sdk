# BLS pairing vectors

`pkgs/pkc/corpus/bls_pairing.json5` records the reference implementation's relic pairing, `pp_map_sim_oatep_k12`, on
every class of point relic can hold, including points off the curve and outside the subgroup, which legacy-scheme
verification reaches, and coordinates at the field's edge values. The inputs are drawn by relic's own seeded generator;
every result comes from the reference implementation's relic.

| File | Role |
|---|---|
| `probe.c` | `fe` mode: compares relic's final exponentiation with blst's on random `Fp12` elements. `pairs` mode: prints pairing vectors as JSON5 |
| `build.sh` | Links `probe.c` against a reference build's `librelic.a` and its generated relic headers, and blst's C sources |

## Regenerating

Build the reference implementation, then build the probe against that tree's relic and the blst release the crate
links:

```sh
contrib/vectors/bls_pairing/build.sh ~/dash-v24.0/src/dashbls/depends/relic/include \
  ~/dash-v24.0/src/dashbls/.libs/librelic.a ~/.cargo/registry/src/*/blst-0.3.17/blst /tmp/pairing-probe
```

Check the final exponentiations, then write the corpus:

```sh
/tmp/pairing-probe fe 1000000 bs11a4-lemma-e
/tmp/pairing-probe pairs 48 bs11a4-corpus > pkgs/pkc/corpus/bls_pairing.json5
```

`fe` exits non-zero unless relic's final exponentiation equals blst's on every element. For a larger replay, write
more pairs to `<dir>/corpus/bls_pairing.json5` and run the test with `BLS_PAIRING_DIR=<dir>`:

```sh
BLS_PAIRING_DIR=<dir> cargo test -p dash-pkc --all-features --lib the_engine_reproduces_relics_pairings
```
