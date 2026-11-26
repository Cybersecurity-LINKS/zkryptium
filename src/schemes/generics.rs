// Copyright 2026 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Clippy compares the real variant with the zero-sized `_Unreachable` marker, or
// BBS+ with CL03 when both features are on. Boxing would add an allocation to every
// value and change the public enum for no benefit.
#![allow(clippy::large_enum_variant)]

use super::algorithms::Scheme;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, marker::PhantomData};

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
use crate::bbsplus::{commitment::BBSplusCommitment, proof::BBSplusBlindPoKSignature};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a blind signature scheme.
pub enum BlindSignature<S: Scheme> {
    #[cfg(feature = "bbsplus")]
    /// BBS+ signature variant
    BBSplus(BBSplusSignature),
    #[cfg(feature = "cl03")]
    /// CL03 signature variant
    CL03(CL03BlindSignature),
    /// Carries the scheme type parameter. It cannot be constructed (`Infallible`) and is never
    /// (de)serialized: decoding it from untrusted input would reach the `panic!` in the accessors.
    #[doc(hidden)]
    #[serde(skip)]
    _Unreachable(PhantomData<S>, Infallible),
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
    /// Carries the scheme type parameter. It cannot be constructed (`Infallible`) and is never
    /// (de)serialized: decoding it from untrusted input would reach the `panic!` in the accessors.
    #[doc(hidden)]
    #[serde(skip)]
    _Unreachable(PhantomData<S>, Infallible),
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
    /// Carries the scheme type parameter. It cannot be constructed (`Infallible`) and is never
    /// (de)serialized: decoding it from untrusted input would reach the `panic!` in the accessors.
    #[doc(hidden)]
    #[serde(skip)]
    _Unreachable(PhantomData<S>, Infallible),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An enum representing a proof of knowledge of a blind signature, with optional
/// committed disclosure of undisclosed messages.
pub enum BlindPoKSignature<S: Scheme> {
    #[cfg(feature = "bbsplus_blind")]
    /// BBS+ blind proof of knowledge signature variant
    BBSplus(BBSplusBlindPoKSignature),
    /// Carries the scheme type parameter. It cannot be constructed (`Infallible`) and is never
    /// (de)serialized: decoding it from untrusted input would reach the `panic!` in the accessors.
    #[doc(hidden)]
    #[serde(skip)]
    _Unreachable(PhantomData<S>, Infallible),
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
    /// Carries the scheme type parameter. It cannot be constructed (`Infallible`) and is never
    /// (de)serialized: decoding it from untrusted input would reach the `panic!` in the accessors.
    #[doc(hidden)]
    #[serde(skip)]
    _Unreachable(PhantomData<S>, Infallible),
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
    /// Carries the scheme type parameter. It cannot be constructed (`Infallible`) and is never
    /// (de)serialized: decoding it from untrusted input would reach the `panic!` in the accessors.
    #[doc(hidden)]
    #[serde(skip)]
    _Unreachable(PhantomData<S>, Infallible),
}
