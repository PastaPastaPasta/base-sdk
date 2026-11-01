`pkgs/params/corpus/chainparams_v23_1.json5` and `chainparams_v24_0.json5` record the chain parameters of the reference
implementation at v23.1.8 and v24.0.0-rc.5, and `brr_payments.json5` its masternode payments around each block reward
reallocation period. `dash-params` checks its chain setup and its period table against them, and `dash-primitives`
checks the genesis block bytes. Every value comes from a dump program linked against the release's own libraries.

* [`chainparams_dump.cpp`](chainparams_dump.cpp) prints, as JSON, the release's parameters of a chain after the release
  parses its options and selects the chain, or the masternode payment at a height.
* [`build.sh`](build.sh) builds a release from `git archive` of its tag in a fresh tree and links the dump program
  against the libraries its node links.
* [`gen.py`](gen.py) runs the dump programs and writes the corpora.

## Regenerating

`build.sh` needs a checkout of [the reference implementation](https://github.com/dashpay/dash) and what its depends
build needs on Linux: autotools, `make`, `pkg-config`, a C++20 compiler and a network connection for the depends
sources. It builds depends without a GUI, wallet, ZMQ or port mapping, configures the release against them and builds
only the libraries its node links. `JOBS` sets the parallel jobs (default 4), and `SOURCES_PATH` a directory of
downloaded depends sources to reuse. Each output directory must be new.

```bash
contrib/params/build.sh ~/dash v23.1.8 /tmp/params-v23
contrib/params/build.sh ~/dash v24.0.0-rc.5 /tmp/params-v24
python3 contrib/params/gen.py --dump /tmp/params-v23 --dump /tmp/params-v24 --out pkgs/params/corpus
```

Each dump program records its tag, the tag's commit and the sha256 of `chainparams_dump.cpp`. `gen.py` refuses a dump
built from another `chainparams_dump.cpp`, and each corpus header names the release and the source's sha256. A v24
release before v24.0.0-rc.5 lacks the pruning depth the dump prints, so it does not build.
