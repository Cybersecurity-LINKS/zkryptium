// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//!# ZKryptium
//! ![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
//! [![](https://img.shields.io/crates/v/zkryptium?style=flat-square)](https://crates.io/crates/zkryptium)
//! [![](https://img.shields.io/docsrs/zkryptium?style=flat-square)](https://docs.rs/zkryptium/)
//! ## Description
//! ZKryptium library provides an implementation of:
//! * **BBS+**([draft-irtf-cfrg-bbs-signatures-09](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-09)) signature scheme
//! * **Blind BBS Signatures** ([draft-irtf-cfrg-bbs-blind-signatures-01](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-01)) signature scheme with some fixes taken from [grotto-bbs-signatures](https://github.com/Wind4Greg/grotto-bbs-signatures)
//! * **BBS per Verifier Linkability** ([draft-irtf-cfrg-bbs-blind-signatures-01](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-01))
//! * **CL2003** (https://link.springer.com/chapter/10.1007/3-540-36413-7_20) signature scheme 
//! This library enables the creation of zero-knowledge proofs, exposing cryptographic primitives facilitating the development of a Verifiable Credentials (VCs) system capable of handling both Anonymous Credentials and Selective Disclosure Credentials.
//! **WARNING:** for CL2003 use a version from v0.3.2 onwards that uses a new secure cryptographic implementation of the Pseudo Random Number Generator [ThreadRng](https://rust-random.github.io/rand/rand/rngs/struct.ThreadRng.html)
//! ## Getting Started
//! ### Requirements
//! - [Rust](https://www.rust-lang.org/) (>= 1.65)
//! - [Cargo](https://doc.rust-lang.org/cargo/) (>= 1.65)
//! - The ZKryptium **CL03** implementation also depends on the [Rug crate](https://crates.io/crates/rug) which depends on GMP, MPFR and MPC libraries through the low-level FFI bindings in the [gmp-mpfr-sys crate](https://crates.io/crates/gmp-mpfr-sys), which needs some setup to build; the [gmp-mpfr-sys documentation](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html) has some details on usage under [GNU/Linux](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html#building-on-gnulinux), [macOS](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html#building-on-macos) and [Windows](https://docs.rs/gmp-mpfr-sys/1.6.1/gmp_mpfr_sys/index.html#building-on-windows).
//! ### Usage
//! ##### BBS+:
//!  ```toml
//! [dependencies]
//! zkryptium = { version = "0.6.0", default-features = false, features = ["bbsplus"] }
//! ```
//! 
//! ##### BBS+ Blind signature:
//! ```toml
//! [dependencies]
//! zkryptium = { version = "0.6.0", default-features = false, features = ["bbsplus", "bbsplus_blind"] }
//! ```
//! 
//! ##### BBS+ per Verifier Linkability:
//!
//! ```toml
//! [dependencies]
//! zkryptium = { version = "0.6.0", default-features = true}
//! ```
//! 
//! ##### CL2003:
//! ```toml
//! [dependencies]
//! zkryptium = { version = "0.6.0", default-features = false, features = ["cl03"] }
//! ```
//! 
//! ### Examples
//! 
//! Take a look at the [examples](https://github.com/Cybersecurity-LINKS/ZKryptium/tree/main/examples).
//! 
//! You can run the examples based on the [BBS+](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) Signature Scheme with:
//! ```sh
//! cargo run --example bbsplus <ciphersuite>
//! cargo run --example bbsplus_blind <ciphersuite>
//! cargo run --example bbsplus_nym <ciphersuite>
//! ```
//! 
//! ##### Available Ciphersuites:
//! - BLS12-381-SHA-256
//! - BLS12-381-SHAKE-256
//! 
//! You can run the examples based on the [CL2003](https://link.springer.com/chapter/10.1007/3-540-36413-7_20) Signature Scheme with:
//! ```sh
//! cargo run --features="cl03" --example cl03 <ciphersuite>
//! cargo run --features="cl03" --example cl03_multiattr <ciphersuite>
//! ```
//! 
//! ##### Available Ciphersuites:
//! - CL1024-SHA-256
//! - CL2048-SHA-256
//! - CL3072-SHA-256
//! ## Test
//! 
//! To test the library you can launch the test vectors with:
//! 
//! ```sh
//! cargo test
//! ```
//! 
#![warn(missing_docs)]


#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

/// Errors module
pub mod errors;
/// Keys module
pub mod keys;
/// Schemes module
pub mod schemes;
/// Utils module
pub mod utils;

#[cfg(feature = "bbsplus")]
/// BBS+ signature scheme module
pub mod bbsplus;
#[cfg(feature = "cl03")]
#[doc(hidden)]
pub mod cl03;
