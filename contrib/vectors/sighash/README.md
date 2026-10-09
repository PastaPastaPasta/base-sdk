# Payload sign-hash vectors

`pkgs/primitives/corpus/sighash.json5` records special transactions Dash Core signed and the keys their signers held;
`gen.py` builds it and `pkgs/primitives/tests/payload_sighash.rs` runs it. No hash in it is recorded: a payload's
`sig_hash_bytes` is right when Core's own signature verifies over its SHA256d.

| Section | Inputs | Checked |
|---|---|---|
| `sighash` | Special transactions from `getblock 2` of dashd v24.0.0-rc.3 on replicas of the regtest chains Core's functional tests build, and on a mainnet node, with the signer's keys at the block before: the operator key and owner address from `protx info` (regtest) or `protx listdiff` (mainnet), the quorum key from `quorum info` of the LLMQ type Core's regtest parameters select, and the collateral script of an external collateral | Core's BLS signature verifies under the key (ProUpServTx, ProUpRevTx, quorum commitments, MnHF signals, asset unlocks); Core's compact ECDSA signatures recover keys whose ids the signer owns (ProRegTx, ProUpRegTx, ProDisTx, ProUpShareTx, ProUpSharedRegTx) |
| `stable_txid` | The asset unlocks of rust-dashcore `dash/tests/data/core_v24_regtest.json`, with dashd's `txid` and, for a version-2 unlock, the `instanceHash` Core prints only then | `Transaction::hash` is the txid, `instance_hash` the instance hash, and `has_stable_txid` holds exactly where Core printed one |

Types 5 and 8 carry no payload signature. A quorum commitment's key enters its sign hash under Core's BLS flag, so the
test checks it under the flag the signature verifies under.

## Regenerating

The extractor is rust-dashcore's `contrib/node/sigvec/extract.py`; it writes one file per chain. Then, from this
directory:

```sh
python3 gen.py --sigvec <extractor output>/*.json \
  --regtest-vectors <rust-dashcore>/dash/tests/data/core_v24_regtest.json \
  --header <header> --out ../../../pkgs/primitives/corpus/sighash.json5
```

`--header` takes the provenance comment at the top of the corpus; copy it from the current file.
