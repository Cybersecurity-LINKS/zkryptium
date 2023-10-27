# ZKryptium

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
[![](https://img.shields.io/crates/v/zkryptium?style=flat-square)](https://crates.io/crates/zkryptium)
[![](https://img.shields.io/docsrs/zkryptium?style=flat-square)](https://docs.rs/zkryptium/)

## Description

<!-- Provide a short description explaining the what, why, and how of your project. Use the following questions as a guide:

- What was your motivation?
- Why did you build this project? (Note: the answer is not "Because it was a homework assignment.")
- What problem does it solve?
- What did you learn? --> 
ZKryptium offers implementations of the [BBS+](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) and [CL2003](https://link.springer.com/chapter/10.1007/3-540-36413-7_20) signature schemes, enabling the creation of zero-knowledge proofs for both signed attributes and signatures.
This library has been designed to expose cryptographic primitives, facilitating the development of a Verifiable Credentials (VCs) system capable of supporting:
- Anonymous Credentials
- Selective Disclosure Credentials




## Getting Started
<!-- What are the steps required to install your project? Provide a step-by-step description of how to get the development environment running. -->

### Requirements

- [Rust](https://www.rust-lang.org/) (>= 1.65)
- [Cargo](https://doc.rust-lang.org/cargo/) (>= 1.65)
- ZKryptium also depends on the [Rug crate](https://crates.io/crates/rug) which depends on GMP, MPFR and MPC libraries through the low-level FFI bindings in the [gmp-mpfr-sys crate](https://crates.io/crates/gmp-mpfr-sys), which needs some setup to build; the [gmp-mpfr-sys documentation](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html) has some details on usage under [GNU/Linux](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html#building-on-gnulinux), [macOS](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html#building-on-macos) and [Windows](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html#building-on-windows).



### Usage

Add this to your Cargo.toml:

```
[dependencies]
zkryptium = "0.1.4"
```

Only BBS+:

```
[dependencies]
zkryptium = { version = "0.1.4", default-features = false, features = ["bbsplus"] }

```

Only CL2003:
```
[dependencies]
zkryptium = { version = "0.1.4", default-features = false, features = ["cl03"] }

```

### Examples

<!-- Provide instructions and examples for use. Include screenshots as needed. -->

Take a look at the [examples](https://github.com/Cybersecurity-LINKS/ZKryptium/tree/main/examples).

You can run the example based on the [BBS+](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) Signature Scheme with:
```
cargo run --example bbsplus <ciphersuite>
```

##### Available Ciphersuites:
- BLS12-381-SHA-256
- BLS12-381-SHAKE-256

You can run the example based on the [CL2003](https://link.springer.com/chapter/10.1007/3-540-36413-7_20) Signature Scheme with:
```
cargo run --example cl03 <ciphersuite>
```
##### Available Ciphersuites:
- CL1024-SHA-256


## Test

To test the library you can launch the test vectors with:

```
cargo test
```
