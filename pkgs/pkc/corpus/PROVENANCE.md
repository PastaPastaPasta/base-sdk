# Corpus provenance

Files directly under `corpus/` that need a recorded origin. `corpus/bls_oracle/` has its own `PROVENANCE.md`.

## bls_dashbls.json5

- Content: the fixed vectors in dashbls' `test.cpp`, copied verbatim (hex strings extracted from the tagged blob by
  script, none typed by hand; the only derived fields are the byte reversals marked "derived" in the file).
- Source: Dash Core v24.0.0-rc.3 (`da567d7db`), `src/dashbls/src/test.cpp`
  (`git show v24.0.0-rc.3:src/dashbls/src/test.cpp`; `src/dashbls/` is unchanged by the program's v24.0 pin).
- Sections and source lines:
  - `pyecc` (1): `test.cpp:319-332`, "IETF test vectors" / "Pyecc vector", basic scheme.
  - `chia_v1` (1 row, 6 signatures/keys and 2 aggregates): `test.cpp:335-402`, "Chia test vectors 1 (Basic)".
  - `legacy_threshold` (1) and `legacy_threshold_shares` (10): `test.cpp:1253-1322`, "Legacy scheme" (the gist
    <https://gist.github.com/xdustinface/318c2c08c36ab12a2b1963caf1f7815c>). `test.cpp:1300` and `:1309` reverse the sign
    hash and each id before use; `*_display` is the hex as written, `*_bytes` the reversed bytes Core signs and passes.
  - `check_valid_basic_g1` (1): `test.cpp:1533-1553`; `check_valid_legacy_g1` (2): `:1576-1597`;
    `check_valid_legacy_g2` (2): `:1599-1620`. The non-legacy G2 case (`:1556-1571`) uses random field elements and
    has no fixed vector.
- Test: `tests/bls_dashbls.rs`.
- `bls_dashbls.json5` sha256 `72cbe119dbf296ff047cc3dbc0ed8ae8eb9c8f3f3119a3c4632361af516f13a7`
