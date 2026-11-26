# Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the BBS+ parsers and for the
verification paths that take Prover-controlled input. They need a nightly toolchain:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

| Target | What it checks |
|--------|----------------|
| `parse` | Every BBS+ `from_bytes` / `from_hex` on arbitrary bytes: no panic, and an accepted value re-encodes to the same bytes. |
| `proof_verify` | `PoKSignature::proof_verify` and `BlindPoKSignature::blind_proof_verify` with fuzzed proof bytes and disclosure choices: no panic, and only a genuine test-vector presentation may verify. |
| `blind_sign` | `BlindSignature::blind_sign` with an untrusted `commitment_with_proof`. |
| `serde` | JSON decoding of the BBS+ types (it bypasses `from_bytes`). |

Build the seed corpus from the draft test vectors in `../fixture_data`, then run a target:

```bash
python3 seeds/make_corpus.py
cargo +nightly fuzz run parse -- -max_total_time=900
```

`corpus/` and `artifacts/` are not versioned. A crash is saved in `artifacts/<target>/` and
can be replayed with `cargo +nightly fuzz run <target> artifacts/<target>/<file>`.
