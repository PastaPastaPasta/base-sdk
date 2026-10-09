# Special-payload vectors

Two corpora in `pkgs/primitives/corpus/` record what Dash Core makes of special-transaction payloads; `gen.py` builds
both, and every outcome in them comes from Core. `pkgs/primitives/tests/payload_core.rs` runs them.

| Corpus | Inputs | Outcomes |
|---|---|---|
| `payload_core.json5` | Crafted payloads: BLS fields of each scheme source with samples from `pkgs/pkc/corpus/bls_wrapper.json5`, NetInfo entries, CbTx v4 with and without the asset-unlock root, and version-3 ProRegTx in the v23.1 layout | `decoderawtransaction` on regtest dashds of v23.1.8 and v24.0.0-rc.3, each under the basic and the legacy BLS flag |
| `v24.json5` | Special transactions from `getblock 2` fixtures of Core-built v24 chains (rust-dashcore `conformance/tests/data`) | The payload objects Core printed for them |

Core prints a payload object only when `GetTxPayload` succeeds, so a null outcome is its decode failure. Lazy operator
keys print through `Get()` under their own scheme, commitment fields under the version's scheme, and the ChainLock,
asset-unlock and MnHF signatures under the flag; a field that decoded invalid prints as zeros.

## Regenerating

Unpack the two release tarballs (check `SHA256SUMS`), then from this directory:

```sh
python3 gen.py probe --release v23.1.8=<dashcore-23.1.8> --release v24.0.0-rc.3=<dashcore-24.0.0-rc.3> \
  --work <scratch dir> --header <header> --out ../../../pkgs/primitives/corpus/payload_core.json5
python3 gen.py v24 --fixtures <rust-dashcore>/conformance/tests/data --header <header> \
  --out ../../../pkgs/primitives/corpus/v24.json5
```

`probe` starts four regtest dashds with private datadirs under `--work` and RPC ports from `--port` (default 29851),
mines one block on each so the flag follows V19, and stops them when done. `--header` takes the provenance comment at
the top of the corpus; copy it from the current file.
