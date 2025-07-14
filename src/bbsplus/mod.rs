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

//! The [BBS (Boneh-Boyen-Shacham) Signature Scheme](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-09) 
//! is a cryptographic protocol optimized for efficient, privacy-preserving, multi-message signatures. 
//! The scheme is based on pairing-based cryptography, allowing a user to compactly sign multiple messages, with the possibility of
//! verifying each individual message in a set without revealing the actual content. This makes BBS signatures well-suited for privacy-sensitive
//! applications such as anonymous credentials and selective disclosures in identity systems.
//! Key characteristics of the BBS Signature Scheme:
//! - **Signature Compactness**: The BBS scheme can sign multiple messages in a compact format, producing a single signature that proves
//!                              the authenticity of all messages in the set. This reduces data overhead in multi-message scenarios.
//! - **Selective Disclosure**: A unique feature of BBS signatures is their ability to selectively reveal certain signed messages while keeping others hidden.
//!                             This functionality supports applications in privacy-preserving systems, such as Verifiable Credentials, where users may only need to disclose specific attributes of their identity.
//! - **Unlinkable Proofs**: This scheme uses a zero-knowledge proof-of-knowledge of the signature, ensuring that a verifier cannot identify the specific signature
//!                             used to generate the proof. This unlinkability makes each BBS proof appear random, even if derived from the same signature, preventing correlation.
//! - **Proof of Possession**: This scheme allows a Prover to demonstrate possession of a signature without revealing it to the Verifier. A "presentation header"
//!                             can also be included, containing contextual information such as a nonce, domain identifier, or validity period. This additional context enhances control over the intended audience or timeframe for the proof.
//! The BBS scheme employs asymmetric cryptographic operations and relies on pairings between groups in elliptic curve cryptography, which allows for compact and efficient operations.
//! # Usage
//! To use the BBS Signature Scheme, enable the `bbsplus` feature in the `Cargo.toml` file
//! ```toml
//! zkryptium = { version = "0.4", default-features = false, features = ["bbsplus"] }
//! ```    



#[cfg(feature = "bbsplus_blind")]
/// Module for blind signatures
pub mod blind;
/// Module for ciphersuites
pub mod ciphersuites;
#[cfg(feature = "bbsplus_blind")]
/// Module for commitments
pub mod commitment;
/// Module for generators
pub mod generators;
/// Module for keys
pub mod keys;
/// Module for proofs
pub mod proof;
/// Module for signatures
pub mod signature;
#[cfg(feature = "bbsplus_nym")]
/// Module for Pseudonyms
pub mod pseudonym;