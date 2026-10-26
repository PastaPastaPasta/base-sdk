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

## bls_pairing.json5

- Content: 48 calls of relic's `pp_map_sim_oatep_k12` (the pairing every dashbls verification runs) with 1 to 4
  pairs each, over every class of point relic can hold: subgroup, on the curve outside the subgroup ("torsion"), the
  G1 points (0, ±2) of order 3, off the curve, G2 with y = 0, projective and Jacobian representations on and off
  the curve, coordinates drawn from 0, 1, 2, -1, -2, (p - 1) / 2, (p + 1) / 2, -4 and random elements ("edge",
  with z = 1 or an edge value), and infinity; and relic's result, the Miller value after `pp_exp_k12`. Coordinates
  are relic's, big-endian.
- Source: `contrib/vectors/bls_pairing/probe.c`, `probe pairs 48 bs11a4-corpus`, which the file's header records
  (the seed replaces relic's urandom seeding, so the command reproduces the file byte for byte), built by its
  `build.sh` against:
  - the `src/dashbls/.libs/librelic.a` of the oracle's Dash Core v24.0.0-rc.3 build, sha256
    `be445a045037e82399667779700f07cfc384557dd91687c4016c01adef4b71be` (`src/dashbls/` is unchanged by the
    program's v24.0 pin and at v24.0.0-rc.4);
  - that build's `src/dashbls/depends/relic/include` (the generated `relic_conf.h` defines the same macros in
    every reference build tree on the generating host);
  - blst 0.3.17's C sources (the crate's `blst/`), which the probe uses only to compare final exponentiations.
- At 10^6 random elements (general, unitary, 0 and 1), `probe fe 1000000 bs11a4-lemma-e` found `pp_exp_k12`
  equal to blst's `blst_final_exp` on every one, so the test compares the engine's Miller value through blst.
- Test: `src/bls/relic/pp.rs`, `the_engine_reproduces_relics_pairings`.
- `bls_pairing.json5` sha256 `287cf2d7ad4e1aee0948a29eaa62774893ff3393d4f207b7802e8fde4fd256a8`
