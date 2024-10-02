// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::string::String;
use thiserror::Error;

#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("Error during keypair generation")]
    KeyGenError(String),
    #[error("Invalid key")]
    KeyDeserializationError,
    #[error("Error during computation of a Blind Signature")]
    BlindSignError(String),
    #[error("Error during computation of a Signature")]
    SignatureGenerationError(String),
    #[error("Not a valid Signature")]
    InvalidSignature,
    #[error("Error during hash to scalar computation")]
    HashToScalarError,
    #[error("Error mapping a message to scalar")]
    MapMessageToScalarError,
    #[error("Not enough Generators")]
    NotEnoughGenerators,
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-coresign) in the `Note` at the end
    #[error(" A == Identity_G1")]
    G1IdentityError,
    #[error("Error during deserialization")]
    DeserializationError(String),
    #[error("Signature is not valid")]
    SignatureVerificationError,
    #[error("Error during computation of a Proof of Knowledge of a Signature")]
    ProofGenError(String),
    #[error("Error during computation of a Blind Proof of Knowledge of a Signature")]
    BlindProofGenError(String),
    #[error("Unknown error")]
    Unspecified,

    #[error("Signature update failed")]
    UpdateSignatureError(String),

    #[error("Invalid Proof of Knowledge of a Signature")]
    InvalidProofOfKnowledgeSignature,
    #[error("Proof of Knowledge of a Signature verification failed")]
    PoKSVerificationError(String),

    #[error("This should NOT happen!")]
    UnespectedError,

    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Invalid commitment proof")]
    InvalidCommitmentProof,

    #[error("Failed to compute the blind challenge")]
    ChallengeComputationFailed,
}
