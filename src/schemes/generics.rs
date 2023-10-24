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

use std::marker::PhantomData;

use serde::{Serialize, Deserialize};

use crate::{bbsplus::{blind::BBSplusBlindSignature, commitment::BBSplusCommitment, proof::{BBSplusPoKSignature, BBSplusZKPoK}, signature::BBSplusSignature}, cl03::{blind::CL03BlindSignature, commitment::CL03Commitment, proof::{CL03PoKSignature, CL03ZKPoK}, signature::CL03Signature}};

use super::algorithms::Scheme;



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BlindSignature<S: Scheme> {
    BBSplus(BBSplusBlindSignature),
    CL03(CL03BlindSignature),
    _Unreachable(std::marker::PhantomData<S>)
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Commitment<S: Scheme> {
    BBSplus(BBSplusCommitment),
    CL03(CL03Commitment),
    _Unreachable(std::marker::PhantomData<S>)
}



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PoKSignature<S: Scheme>{
    BBSplus(BBSplusPoKSignature),
    CL03(CL03PoKSignature),
    _Unreachable(PhantomData<S>)
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ZKPoK<S: Scheme> {
    BBSplus(BBSplusZKPoK),
    CL03(CL03ZKPoK),
    _Unreachable(PhantomData<S>)
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Signature<S: Scheme> {
    BBSplus(BBSplusSignature),
    CL03(CL03Signature),
    _Unreachable(PhantomData<S>)
}
