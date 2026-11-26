# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (for 0.x releases, a minor
version bump may contain breaking changes).

## [0.9.0] - 2026-11-26

This release updates Blind BBS and BBS per Verifier Linkability to the latest drafts, aligns BBS with
draft 15, and is the result of a security review of the whole crate. It contains breaking changes:
see [Changed](#changed) and [Removed](#removed).

### Security

- **Forged BBS presentations (all releases up to 0.8.2, and 0.8.3 when proofs are decoded with
  serde).** A proof with `Abar = Bbar = Identity_G1` satisfies the pairing check, and the remaining
  part of the verification can then be satisfied without a signature: anyone who knows only the
  Issuer public key could produce a proof that verifies for arbitrary disclosed messages. In 0.8.2
  and earlier `PoKSignature::from_bytes` accepted such proofs; 0.8.3 rejects them in `from_bytes`,
  but the serde `Deserialize` implementations still accepted them. The checks required by the drafts
  (no identity `Abar`, `Bbar`, `D`, commitments, signature `A` or public key) are now part of the
  verification itself, so they apply to BBS, Blind BBS and pseudonym proofs whatever their source.
  **Users of 0.8.2 or earlier should upgrade.**
- Malformed presentations no longer crash the Verifier (denial of service):
  - `PoKSignature::proof_verify` panicked when the numbers of disclosed messages and indexes differed;
  - `proof_verify_with_nym` underflowed on a crafted proof;
  - serde accepted the `_Unreachable` variant of the generic enums, on which every verification
    panicked;
  - the CL03 verifiers panicked on non-invertible group elements, truncated vectors or short
    encodings.
- CL03: from a signature on `m`, a valid signature on `m + k·e` could be derived. Messages outside
  `[0, 2^lm)` are now rejected by signing and verification.
- Secret keys, blind factors and nym secrets are zeroized on drop (best effort), and secret keys
  (BBS+ and CL03) and blind factors print `<redacted>` in `Debug`.

### Changed

- **Blind BBS** follows [draft-irtf-cfrg-bbs-blind-signatures-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05):
  - messages are `bbsplus::commitment::Message` values (`Message::hash` or `Message::raw`) instead of
    `Vec<u8>` in `Commitment::commit`, `BlindSignature::blind_sign` and `verify_blind_sign`;
  - blind proofs move from `PoKSignature` to the new `BlindPoKSignature`, with committed disclosure
    of undisclosed messages: `blind_proof_gen(pk, signature, BlindProofGenInput)` returns the proof
    and an `AddZkpInfo`; `blind_proof_verify(pk, BlindProofVerifyInput)` takes one `Disclosure`
    (`Disclose`, `Hide`, `Commit`) per message instead of disclosed index lists;
  - `bbsplus::blind::calculate_b` takes the public key, both generator sets, the header and the
    API id.
- **BBS per Verifier Linkability** follows [draft-irtf-cfrg-bbs-per-verifier-linkability-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05):
  - `proof_gen_with_nym` and `proof_verify_with_nym` move to `BlindPoKSignature` and take
    `BlindProofGenInput` / `BlindProofVerifyInput`; `proof_gen_with_nym` also returns an `AddZkpInfo`;
  - `commit_with_nym` and `blind_sign_with_nym` take `Message` values;
    `verify_finalize_with_nym` takes a `VerifyFinalizeWithNymInput`.
- **BBS** references [draft-irtf-cfrg-bbs-signatures-15](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15)
  (no algorithm or test vector changes). The draft now requires the Prover to verify a signature on
  receipt: `proof_gen`, `blind_proof_gen` and `proof_gen_with_nym` document this and do not verify it
  themselves. The plain BBS API (`sign`, `verify`, `proof_gen`, `proof_verify`, key generation) is
  unchanged.
- `PoKSignature::proof_verify` accepts disclosed indexes in any order (each message stays paired
  with its index) and rejects repeated indexes.
- `Error` has new variants: `InvalidNumberOfBlindGenerators`, `InvalidMessageFlag`,
  `InvalidNymSecretsLength`.
- `ScalarExt` has a new required method, `from_os2ip_be`.
- `AddZkpInfo` implements `Drop` (zeroization), so its fields can no longer be moved out by
  destructuring.
- The `_Unreachable` variant of the generic enums (`Signature`, `PoKSignature`, ...) is now
  `_Unreachable(PhantomData<S>, Infallible)`: it cannot be constructed, and serde does not
  serialize or deserialize it.
- **CL03**:
  - `Signature::sign`, `sign_multiattr`, `BlindSignature::blind_sign` and `update_signature` return
    `Result`;
  - the `from_bytes` functions of signatures and keys return `Result`;
  - `blind_sign` takes a `CL03BlindSignInput`; revealed messages and their indexes are one
    `CL03RevealedMessages` value (in `CL03BlindSignInput` and `update_signature`); the trusted
    commitment and its key are one `CL03TrustedCommitment` value in `ZKPoK::generate_proof` and
    `verify_proof`;
  - new `CL03Message::is_in_range`.
- Dependencies: `bls12_381_plus` 0.10, `elliptic-curve`, `ff` and `group` 0.14, `sha2` and `digest`
  0.11, `rand` and `rand_chacha` 0.10; `sha3` is replaced by `shake`, and `hash2curve` 0.14 provides
  `expand_message`. Types from these crates appear in the public API, so they change version too.
  `BbsCiphersuite::Expander` is bound by `ExpandMsg<SecurityLevel>` (new alias `SecurityLevel`),
  and code that wrote `for<'a> ExpandMsg<'a>` bounds must drop them.
- The BBS+-only dependencies (`ff`, `group`, `elliptic-curve`, `hash2curve`, `shake`, `zeroize`) are
  optional and enabled by the `bbsplus` feature: a `cl03`-only build pulls 50 crates instead of 94.
- Minimum supported Rust version: **1.88** (was declared as 1.65).

### Added

- `BlindPoKSignature`, `BBSplusBlindPoKSignature` (with `from_bytes(bytes, commitments_count)`,
  `to_bytes`, `commitments`), `Disclosure`, `AddZkpInfo`, `recompute_commitments` and
  `committed_disclosure_generators` for committed disclosure in Blind BBS proofs.
- `Message` (`HASH` / `RAW` flags of the Blind BBS draft) and its `TryFrom<(String, Vec<u8>)>`.
- Input structs `BlindProofGenInput`, `BlindProofVerifyInput`, `VerifyFinalizeWithNymInput`.
- Fuzz targets for the BBS+ parsers and verification paths (`fuzz/`, cargo-fuzz).
- CI: clippy with `-D warnings` on every BBS+ feature combination, an MSRV job, and a weekly
  `cargo audit`.
- License note: the optional `cl03` feature depends on LGPL-3.0-or-later crates (`rug`,
  `gmp-mpfr-sys`, which links GMP, MPFR and MPC statically).

### Fixed

- `from_bytes` of BBS+ commitments, ZKPoKs and pseudonyms reject zero scalars, the identity and the
  base point where the drafts require it; `PseudonymSecret::from_hex` no longer panics on malformed
  input.
- `deserialize_and_validate_commit` rejects a number of blind generators different from the
  commitment's; `blind_sign` and `blind_sign_with_nym` validate the commitment before creating
  generators.
- Blind and nym signing and proof generation return errors instead of panicking on invalid inputs
  (empty or too many nym secrets, invalid `length_nym_vector`, revealed nym secrets).
- `core_sign` returns an error instead of panicking if `SK + e` is not invertible.
- CL03: `blind_sign` no longer panics on an invalid Prover ZKPoK; revealed messages without indexes
  are rejected instead of ignored; the trusted commitment check is always performed;
  `verify_multiattr` checks the upper bound of `e`.
- Examples exit with a non-zero code on error; the Blind BBS example decodes message values
  correctly.
- The library no longer prints to stdout.

### Removed

- `KeyPair::write_keypair_to_file` (it wrote the private key in plain JSON and panicked on I/O
  errors). `serde_json` is now only a dev-dependency.
- `bbsplus::blind::prepare_parameters`.
- `PoKSignature::blind_proof_gen`, `blind_proof_verify`, `proof_gen_with_nym` and
  `proof_verify_with_nym` (moved to `BlindPoKSignature`).
- From the public API of `utils::util::bbsplus_utils`: `multi_exponentiation_g1`, `serialize`,
  `get_messages`, `get_generators_from_indexes`, `calculate_random_scalars`,
  `calculate_blind_challenge` (internal helpers that panicked on inconsistent input).

### Known issues

- CL03: the range proofs and proofs of knowledge of hidden messages are not bound to the
  commitment, and the `PublicKey` / `PrivateKey` traits are not implemented for CL03 keys.
- With both `cl03` and `bbsplus` enabled, decoding a value of the other scheme into a generic enum
  (e.g. a CL03 proof as `PoKSignature<BBSplus<_>>`) makes the accessors panic.

## [0.8.3] - 2026-11-23

### Fixed

- BBS+ `from_bytes` parsers reject the identity element ([#22](https://github.com/Cybersecurity-LINKS/zkryptium/pull/22)).

## [0.8.2] - 2026-11-16

### Fixed

- BBS+ `from_bytes` parsers check the input length ([#21](https://github.com/Cybersecurity-LINKS/zkryptium/pull/21)).

[0.9.0]: https://github.com/Cybersecurity-LINKS/zkryptium/compare/v0.8.3-alpha...HEAD
[0.8.3]: https://github.com/Cybersecurity-LINKS/zkryptium/compare/v0.8.2-alpha...v0.8.3-alpha
[0.8.2]: https://github.com/Cybersecurity-LINKS/zkryptium/compare/v0.8.1-alpha...v0.8.2-alpha
