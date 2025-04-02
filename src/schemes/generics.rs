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

use super::algorithms::Scheme;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[cfg(feature = "cl03")]
use crate::cl03::{
    blind::CL03BlindSignature,
    commitment::CL03Commitment,
    proof::{CL03PoKSignature, CL03ZKPoK},
    signature::CL03Signature,
};

#[cfg(feature = "bbsplus")]
use crate::bbsplus::{
    proof::{BBSplusPoKSignature, BBSplusZKPoK},
    signature::BBSplusSignature,
};

#[cfg(feature = "bbsplus_blind")]
use crate::bbsplus::commitment::BBSplusCommitment;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a blind signature scheme.
pub enum BlindSignature<S: Scheme> {
    #[cfg(feature = "bbsplus")]
    /// BBS+ signature variant
    BBSplus(BBSplusSignature),
    #[cfg(feature = "cl03")]
    /// CL03 signature variant
    CL03(CL03BlindSignature),
    /// Unreachable variant to satisfy the type system
    _Unreachable(std::marker::PhantomData<S>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a commitment scheme.
pub enum Commitment<S: Scheme> {
    #[cfg(feature = "bbsplus_blind")]
    /// BBS+ commitment variant
    BBSplus(BBSplusCommitment),
    #[cfg(feature = "cl03")]
    /// CL03 commitment variant
    CL03(CL03Commitment),
    /// Unreachable variant to satisfy the type system
    _Unreachable(std::marker::PhantomData<S>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a proof of knowledge signature scheme.
pub enum PoKSignature<S: Scheme> {
    #[cfg(feature = "bbsplus")]
    /// BBS+ proof of knowledge signature variant
    BBSplus(BBSplusPoKSignature),
    #[cfg(feature = "cl03")]
    /// CL03 proof of knowledge signature variant
    CL03(CL03PoKSignature),
    /// Unreachable variant to satisfy the type system
    _Unreachable(PhantomData<S>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a zero-knowledge proof of knowledge scheme.
pub enum ZKPoK<S: Scheme> {
    #[cfg(feature = "bbsplus")]
    /// BBS+ zero-knowledge proof of knowledge variant
    BBSplus(BBSplusZKPoK),
    ///CL03 zero-knowledge proof of knowledge variant
    #[cfg(feature = "cl03")]
    CL03(CL03ZKPoK),
    /// Unreachable variant to satisfy the type system
    _Unreachable(PhantomData<S>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a signature scheme.
pub enum Signature<S: Scheme> {
    #[cfg(feature = "bbsplus")]
    /// BBS+ signature variant
    BBSplus(BBSplusSignature),
    #[cfg(feature = "cl03")]
    /// CL03 signature variant
    CL03(CL03Signature),
    /// Unreachable variant to satisfy the type system
    _Unreachable(PhantomData<S>),
}
