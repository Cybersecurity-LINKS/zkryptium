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

use thiserror::Error;

#[derive(Error, Clone, Debug)]
/// Enum representing various errors that can occur in the application.
pub enum Error {
    ///Error during keypair generation
    #[error("Error during keypair generation")]
    KeyGenError(String),
    ///Invalid key
    #[error("Invalid key")]
    KeyDeserializationError,
    ///Error during computation of a Blind Signature
    #[error("Error during computation of a Blind Signature")]
    BlindSignError(String),
    ///Error during computation of a Signature
    #[error("Error during computation of a Signature")]
    SignatureGenerationError(String),
    ///Not a valid Signature
    #[error("Not a valid Signature")]
    InvalidSignature,
    ///Error during hash to scalar computation
    #[error("Error during hash to scalar computation")]
    HashToScalarError,
    ///Error mapping a message to scalar
    #[error("Error mapping a message to scalar")]
    MapMessageToScalarError,
    ///Not enough Generators
    #[error("Not enough Generators")]
    NotEnoughGenerators,
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-09#name-coresign) in the `Note` at the end
    #[error("Error, B value is Identity_G1")]
    G1IdentityError,
    ///Error during deserialization
    #[error("Error during deserialization")]
    DeserializationError(String),
    ///Signature is not valid
    #[error("Signature is not valid")]
    SignatureVerificationError,
    ///Error during computation of a Proof of Knowledge of a Signature
    #[error("Error during computation of a Proof of Knowledge of a Signature")]
    ProofGenError(String),
    ///Error during computation of a Blind Proof of Knowledge of a Signature
    #[error("Error during computation of a Blind Proof of Knowledge of a Signature")]
    BlindProofGenError(String),
    ///Unknown error
    #[error("Unknown error")]
    Unspecified,
    ///Signature update failed
    #[error("Signature update failed")]
    UpdateSignatureError(String),
    ///Invalid Proof of Knowledge of a Signature
    #[error("Invalid Proof of Knowledge of a Signature")]
    InvalidProofOfKnowledgeSignature,
    ///Proof of Knowledge of a Signature verification failed
    #[error("Proof of Knowledge of a Signature verification failed")]
    PoKSVerificationError(String),
    ///UnespectedError This should NOT happen!
    #[error("This should NOT happen!")]
    UnespectedError,
    ///Invalid commitment
    #[error("Invalid commitment")]
    InvalidCommitment,
    ///Invalid commitment proof
    #[error("Invalid commitment proof")]
    InvalidCommitmentProof,
    ///Failed to compute the blind challenge
    #[error("Failed to compute the blind challenge")]
    ChallengeComputationFailed,
    ///Invalid number of Generators
    #[error("Invalid number of Generators")]
    InvalidNumberOfGenerators,
    ///Error during serialization of the pseudonym
    #[error("Error during serialization of the pseudonym")]
    InvalidPseudonym,
}
