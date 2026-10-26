# Corpus provenance

Files directly under `corpus/` that need a recorded origin. `corpus/bls_oracle/` has its own `PROVENANCE.md`.

The ten files from `bls_aggregate.json5` on came from upstream (Kittywhiskers Van Gogh) without a generator, and their
bytes are kept as they are. `contrib/vectors/bls_oracle/check_upstream.py` has Core reproduce their values through
the consensus oracle (its README, "Checking the upstream files", gives the classes it reports):

- Upstream revision: the copies checked are upstream `33fcc59e` (2026-10-04)'s, `bls_dh.json5` aside (its section
  gives this fork's change). Upstream `7f6b0ea6` (2026-10-14) later adds `sign_message` to `bls_sign.json5` and
  `verify_message` to `bls_aggregate.json5` and `bls_secure_aggregate.json5`: raw-message signing, where Core signs
  a uint256, so some of those values may not be reachable. The checker has no checks for them yet and stops on those
  files when run on that revision's copies.

- Dash Core commit `77dbec82427cfa91d420825235ca0f7abf5c984e` (branch `node/bl211-oracle-v24.0`): v24.0.0-rc.3 plus
  the oracle shim, ABI 28. `src/bls/`, `src/dashbls/`, `src/llmq/commitment.cpp` and `src/active/dkgsession.cpp` are
  unchanged from v24.0.0-rc.3.
- Archive `libdash_oracle_v24_0.a` (plain flavour) sha256
  `ceae0c8a05149c25e523a811f84f9b432dfa4f3c6b77bc7fcc4b3901e5daa519`; probe: `contrib/vectors/bls_oracle/build.sh
  <archive> <probe>`.
- A "chia" section is Core's legacy scheme and an "ietf" section its basic one, as the crate's `BlsScChia` and
  `BlsScIetf`; messages are uint256s in their stored order, as Core signs a hash.

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

## bls_aggregate.json5

- Content: `base.sk`, AggregateInsecure of 2, 3 and 5 secret keys (scheme-independent); per scheme, `pk` and `sig`,
  AggregateInsecure of 2, 3 and 5 keys and signatures, and `verify`, the aggregate of signatures over distinct
  messages (and over one repeated message) with VerifyInsecureAggregated's verdict, `accepted` (the repeated message
  is refused under the basic scheme only).
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22, "pkc%feat: initial code release") as
  `bls_aggregate.json` and `bls_{chia,ietf}_aggregate.json`; `6045c997e6b6` (2026-08-11) added `verify`;
  `769b2fd0c335` made them JSON5 and `3fd972fa4d84` (2026-08-17) merged the three files.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim: every aggregate, every verdict, and each `verify`
  aggregate re-signed with `base.sk`'s keys (Core derives the rows' keys from them). The aggregated keys and
  signatures and the messages are inputs (Core reads the keys and signatures back). Checker: 129 values,
  31 reproduced, 98 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/secret_ops.rs`, `src/bls/public_ops.rs` and `src/bls/sig_aggregate.rs`, `aggregate_matches_vectors`;
  `src/bls/sig_aggregate.rs`, `aggregate_verify_matches_vectors`.
- `bls_aggregate.json5` sha256 `9a1a638e6fee731061d97d1c7fc96bdd60b90b4d695d2cfb257f16bf6b9c45c5`

## bls_dh.json5

- Content: per scheme, `dh`, DHKeyExchange for two key pairs, and `ies`, one CBLSIESMultiRecipientBlobs encryption to
  three recipients with a fixed ephemeral key and IV seed: the ephemeral public key and, per recipient, the key pair,
  the shared point, the IV, the plaintext and the ciphertext.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_{chia,ietf}_dh.json` (`dh`), merged in
  `04d5482ba5b1` (2026-08-17); `b99a9013ba03` (2026-08-25, "pkc%feat(bls): implement BLS-IES") added `ies`. This
  fork's `48870f3e3874` (pasta, 2026-10-22, not upstream) replaced the three `chia.ies` ciphertexts: Core keys every
  blob with the basic encoding of the shared point under both schemes, and the checker reports upstream's three, and
  their IVs, as not reproduced.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim. The ephemeral key and the seed are the randomness
  InitEncrypt draws, and the oracle takes both, so Core encrypts with them: the ephemeral public key, each recipient's
  key, each shared point (from either side), each ciphertext (the blobs of Core's container) and each plaintext (Core's
  decryption). Each IV is glue, the seed through sha256d i times (`GetIV`, `src/bls/bls_ies.cpp`), and Core decrypts
  the ciphertext under it to the plaintext. Checker: 54 values, 30 reproduced (6 by glue), 24 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/scheme_chia.rs`, `src/bls/scheme_ietf.rs` and `src/bls/public_ops.rs`, `dh_exchange_matches_vectors`;
  `src/bls/ies_ops.rs`, `kat_key_material_matches_the_reference`, `kdf_reads_the_basic_encoding`,
  `kat_encrypt_matches_the_reference` and `kat_decrypt_matches_the_reference`.
- `bls_dh.json5` sha256 `5b57b8940fce0036953bae48c8f11854e66871fb75e08315787acf0c8b88ae9d`

## bls_hash.json5

- Content: `chia`, three messages through the legacy hash to G2: for each of its four field elements, the two SHA-256
  digests of the message, a tag (`G2_0_c0` to `G2_1_c1`) and a counter (`tNN_hash`), the element reduced from them
  (`tNN_fp`), and the point under the legacy (`hash_to_g2_legacy`) and basic (`hash_to_g2_uncomp`) serializations.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_chia_hash_internals.json`, renamed in
  `b211cccfdc03` (2026-08-17); values unchanged.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim, except the 24 intermediates `tNN_hash` and `tNN_fp`,
  which are not reachable: Core exposes dashbls' legacy hash to G2 only as the point (HASH_TO_G2,
  `CBLSSecretKey(1).Sign(h)`). Both serializations of the point are reproduced. Checker: 33 values, 6 reproduced,
  24 not reachable, 3 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/chia_h2c.rs`, `hash_to_fp_matches_vectors` (it reads the intermediates only).
- `bls_hash.json5` sha256 `70a93cfd281aff4ce8c3e7aa57f6df080fd0df1a1b2ab6ac1ebe3b63e0ecf18f`

## bls_ies.json5

- Content: per scheme, serialized CBLSIESEncryptedBlob (`blob`, data of 0, 16, 32, 252 and 253 bytes) and
  CBLSIESMultiRecipientBlobs (`multi`, blob lengths `[]`, `[0]`, `[16]`, `[16, 0, 32]` and `[252, 253]`) images,
  with the ephemeral key of KeyGen(`0x01 * 32`), the seed `0x01 * 32` and filler data, and their lengths.
- Source: upstream `1803db1fea17` (Kittywhiskers Van Gogh, 2026-08-29, "pkc%feat(bls): implement byte bags for
  BLS-IES encrypted blobs").
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim, with a fixed ephemeral secret key
  `6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220` (KeyGen of `0x01 * 32` as
  `src/bls/secret_ops.rs`'s `keygen_uses_draft03_variant` records it) and IV seed `0x01 * 32` (as `src/bls/ies_bytes.rs`
  asserts). Each image whose blob lengths are multiples of 16 is Core's encryption, under that key and seed, of the
  plaintext Core decrypts from the image. The filler survives that round trip whatever it is: Core fixes the ephemeral
  public key, the seed and the layout, not the filler. The six images (three per scheme) holding a blob of 252 or 253
  bytes are not reachable for their filler: Core's IES encryption (AES-256-CBC without padding) refuses those lengths,
  so no op writes that data. Core still writes the container around a blob it refuses, with the blob zero-filled, so
  each of these images with its filler zeroed is checked against that: the ephemeral public key and seed from Core's
  encryption of zero-filled blobs of all the image's lengths, the blob count, and each blob's length prefix from an
  encryption of that blob alone (blobs after a refused one come out empty). Core reads each image whole and refuses it
  one byte longer. The lengths are checked against the images' layout. Checker: 44 values, 14 reproduced, 6 not
  reachable (filler only), 24 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/ies_bytes.rs`, `codec_matches_the_reference`.
- `bls_ies.json5` sha256 `0f2845f5a7cefb693ff55c20961ba16e12f76c764772edaafba34dc6023d24ae`

## bls_keygen.json5

- Content: per scheme, `derive_pk`, the secret keys `0x01 * 32` to `0x05 * 32` and their public keys.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_{chia,ietf}_keygen.json`, merged in
  `4407ecbd157f` (2026-08-17); values unchanged.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim (GetPublicKey); the secret keys are inputs Core reads
  back. Checker: 20 values, 10 reproduced, 10 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/secret_ops.rs`, `derive_public_key_matches_vectors`.
- `bls_keygen.json5` sha256 `f0bffa4135698d63f2cd4bfd452d257661e92d3860fbb455c39a4edb27fa1964`

## bls_llmq_100.json5

- Content: per scheme, a three-member, threshold-2 DKG of LLMQ type 100 as Core runs it (`src/active/dkgsession.cpp`):
  each member's verification vector and secret key shares (`contribute`), every member's check of the shares it
  received (`verify`), each member's premature commitment (`commit`: the valid members, the quorum verification
  vector, its hash and the quorum public key, the member's key share, the commitment hash, `quorum_sig_share` =
  `skShare.Sign(commitmentHash)` and `member_sig`, the operator key's signature of it) and the final commitment
  (`finalize`: the signers' threshold signatures and the quorum signature Recover gives, the operator keys and
  signatures and their AggregateSecure). Ids and hashes are written as `uint256::GetHex` prints them, the stored
  bytes reversed.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_{chia,ietf}_llmq_100.json`, merged in
  `5d3e57d4674a` (2026-08-17); `c9eefdff3423` (2026-09-14) and `9b022b5c2e73` (2026-09-15) re-spelled the member and
  signer ids, first all in stored order and then all in GetHex order. No other value changed.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim, with two kinds checked by Core's verification
  instead, as the file does not record their randomness: the contributions' secret key shares (the polynomial
  coefficients are not recorded; GetPublicKey(share) equals PublicKeyShare(vvec, id), Core's check) and the operator
  signatures `member_sig` and `member_sigs` (the operator secret keys are not recorded; VerifyInsecure by
  `member_pks` of the commitment hash). The verdicts, the quorum verification vector and public key, the key shares,
  the signatures, the recovered signature and the members' aggregate are Core's; `quorum_vvec_hash` and
  `commitment_hash` are glue over Core's outputs (`::SerializeHash` and `BuildCommitmentHash`, sha256d over Core's
  serialization). Checker: 260 values, 70 reproduced (12 by glue), 30 verified, 160 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/share_ops.rs`, `llmq_contribute_vvec`, `llmq_contribute_sk_shares`, `llmq_verify_contributions`,
  `llmq_commit_quorum_key`, `llmq_commit_sk_share`, `llmq_commit_sig`, `llmq_finalize_recover_quorum_sig` and
  `llmq_finalize_aggregated_member_sigs` (the last three sign and verify their own signatures rather than compare the
  recorded ones).
- `bls_llmq_100.json5` sha256 `72bec3e551d22a6b511b87e73bbc8f0215736a91bf9ee7efe79ac514c8c33557`

## bls_secure_aggregate.json5

- Content: per scheme, AggregateSecure of the signatures of one message by 3 and by 5 keys (`agg_sig_secure`), with
  the signers' keys and signatures.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_{chia,ietf}_secure_aggregate.json`,
  merged in `d167531424b1` (2026-08-17); values unchanged.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim: each aggregate (VerifySecureAggregated also holds),
  and each signature re-signed with the secret key (`0x01 * 32` to `0x05 * 32`, recorded in `bls_keygen.json5` and
  others) from which Core derives the row's key. The keys and the message are inputs (Core reads the keys back).
  Checker: 40 values, 20 reproduced, 20 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/public_ops.rs`, `secure_aggregate_is_what_verify_checks`; `src/bls/sig_aggregate.rs`,
  `secure_aggregate_matches_vectors` and `secure_verify_matches_vectors`.
- `bls_secure_aggregate.json5` sha256 `18acd412bb0ca096eab2a940b1aa4dd017d30748331488dafc2e96d201b53ce8`

## bls_serialize.json5

- Content: five public keys and five signatures, each under the legacy (`chia`) and the basic (`ietf`) serialization
  at the same index: the public keys of `bls_keygen.json5` and the `chia` signatures of `bls_sign.json5`'s first
  message.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_chia_ser_internals.json`, reshaped into
  `bls_serialize.json5` in `e026cbee2df3` (2026-08-17); values unchanged.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim: each value is Core's serialization, under its
  scheme, of its partner decoded under the other, and Core reads it back byte for byte. Checker: 20 values,
  20 reproduced.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/tests.rs`, `ser_pairs`, which `src/bls/scheme_chia.rs` (`signature_serialization_matches_vectors`),
  `src/bls/sig_basic.rs` and `src/bls/public_ops.rs` (`serialization_formats_match_vectors` and others) read.
- `bls_serialize.json5` sha256 `94a988942e3de854ea991da2406c8d4879e1cfc0da706c3729dc86f67428ae79`

## bls_sign.json5

- Content: per scheme, the signatures by the secret keys `0x01 * 32` to `0x05 * 32` of three messages.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_{chia,ietf}_sign.json`, merged in
  `af0b86dfe08d` (2026-08-17); values unchanged.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim (Sign); the keys and messages are inputs (Core reads
  the keys back). Checker: 90 values, 30 reproduced, 60 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/scheme_chia.rs`, `src/bls/scheme_ietf.rs` and `src/bls/sig_basic.rs`, `signing_matches_vectors`.
- `bls_sign.json5` sha256 `205383ce6c5fae6491f97d953cc3fbc8c675742f150162005724172b1b0366ba`

## bls_threshold.json5

- Content: per scheme, a threshold-3 split of the master keys `0x01 * 32`, `0x02 * 32` and `0x03 * 32` over the
  ids 1 to 5 (a uint256 whose stored bytes, read big-endian, are the id): the secret key shares, their signatures of one
  message, the signature Recover gives from shares 1, 3 and 5, and the first master key's own signature.
- Source: upstream `ff3499594d2b` (Kittywhiskers Van Gogh, 2026-04-22) as `bls_{chia,ietf}_threshold.json`, merged in
  `67ef6b3206a7` (2026-08-17); values unchanged.
- Values reproduced by Core v24.0.0-rc.3 through the oracle shim (SecretKeyShare, Sign and Recover of the recorded
  shares); the master keys, the message, the ids and the counts are inputs. Checker: 42 values, 24 reproduced,
  18 inputs.
- Checker: `python3 contrib/vectors/bls_oracle/check_upstream.py --probe <probe> --corpus-dir pkgs/pkc/corpus`.
- Test: `src/bls/sig_threshold.rs`, `recovery_matches_vectors`.
- `bls_threshold.json5` sha256 `6073351b70ecfb01c4711a0749984182d02901a3fb20603a0b85c83636ec9995`
