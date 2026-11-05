The programs here write the BLS corpora below in `pkgs/pkc/corpus` from a reference implementation release. Every value
comes from the release's BLS library (dashbls, with relic) or from its own sources, namely its BLS wrapper,
serialization and hashing, and commitment hash function, apart from fixed inputs at the top of each program and in
`util/common.hpp`.

| Corpus | Program |
| --- | --- |
| `bls_aggregate.json5` | `gen_aggregate.cpp` |
| `bls_hash.json5` | `gen_hash.cpp` |
| `bls_ies.json5` | `gen_ies.cpp` |
| `bls_keygen.json5` | `gen_keygen.cpp` |
| `bls_llmq_100.json5` | `gen_llmq_100.cpp` |
| `bls_read.json5` | `gen_read.cpp` |
| `bls_secure_aggregate.json5` | `gen_secure_aggregate.cpp` |
| `bls_serialize.json5` | `gen_serialize.cpp` |
| `bls_sign.json5` | `gen_sign.cpp` |
| `bls_threshold.json5` | `gen_threshold.cpp` |

Each program prints its corpus on stdout. For `bls_llmq_100.json5`, its `member_pks` and `member_sig` values are fixed
inputs, which the program checks against the commitment hash it computes. For `bls_hash.json5`, the program repeats the
legacy map's hashing and reduction steps with relic, which the library does not expose. It then runs the map's own
encoding and cofactor steps on the field elements it writes, and stops unless they give the library's point. That ties
every value but the order of the two pairs of tags, which the sum of their encodings does not show.

`bls_read.json5` records how the library reads key and signature bytes under each scheme, as `gen_read.cpp` describes.

## Regenerating

`regen.py` needs Python 3.11.4 or later, git, CMake, a C compiler, a C++20 compiler, Boost and GMP, all of which the
development shell provides. The `dash` submodule pins the release, and `regen.py` checks it out when it is not yet. It
extracts the release's `src` into `target/bls-corpus` and applies two patches: one restores the relic CMake
configuration template the release leaves out, and one gives two steps of the legacy map external linkage for
`gen_hash.cpp`. It builds the library and the programs there with CMake. The build is kept for later runs with the same
compilers, flags, generator and patches. Nothing is written unless every program succeeds.

```bash
pkgs/pkc/contrib/regen.py
```

To write one corpus, or to write somewhere else:

```bash
pkgs/pkc/contrib/regen.py --program keygen --corpus /tmp/bls
```

`regen.py` stops when the submodule is not checked out at the staged pin, for example after a pull that moved the pin.
This checks it out at the staged pin:

```bash
git submodule update --init --checkout -- pkgs/pkc/contrib/dash
```

To write the corpora from another release, check the submodule out first, then fetch and check out the release's tag in
it and stage it.
