use std::marker::{PhantomData};

use bls12_381_plus::{G1Projective, Scalar, G1Affine};
use elliptic_curve::{group::Curve, subtle::{CtOption, Choice}};
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::ciphersuites::BbsCiphersuite, cl03::ciphersuites::CLCiphersuite, keys::cl03_key::{CL03PublicKey, CL03SecretKey}, utils::random::{random_prime, random_bits}};

use super::commitment::CL03Commitment;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusBlindSignature {
    pub(crate) a: u32,
    pub(crate) e: u64,
    pub(crate) s: u32,
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03BlindSignature {
    pub(crate) e: u8,
    pub(crate) rprime: u8,
    pub(crate) v: u8,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BlindSignature<S: Scheme> {
    BBSplus(BBSplusBlindSignature),
    CL03(CL03BlindSignature),
    _Unreachable(std::marker::PhantomData<S>)
}

impl <CS:BbsCiphersuite> BlindSignature<BBSplus<CS>> {
    pub fn get_params(&self) -> (u32, u64, u32) {
        match self {
            Self::BBSplus(inner) => (inner.a, inner.e, inner.s),
            Self::CL03(_) => panic!(),
            Self::_Unreachable(_) => panic!(),
        }
    }

    pub fn prova() -> Self{
        let s = BBSplusBlindSignature{ a: 1, e: 2, s: 3 };
        Self::BBSplus(s)
    }
}

impl <CS:CLCiphersuite> BlindSignature<CL03<CS>> {
    pub fn get_params(&self) -> (u8, u8, u8) {
        match self {
            Self::CL03(inner) => (inner.e, inner.rprime, inner.v),
            Self::BBSplus(_) => panic!(),
            Self::_Unreachable(_) => panic!(),
        }
    }

    pub fn prova2() -> Self{
        let s = CL03BlindSignature{e: 4, rprime: 5, v: 6};
        Self::CL03(s)
    }
}



// pub trait BlindSignature {
//     type SignatureType;
//     // type Params;

//     // fn get_params(&self) -> Self::Params;
//     // fn sign() -> Self;
// }

// impl BlindSignature for CL03BlindSignature {
//     type SignatureType = Self;
//     // type Params = (u8, u8, u8);

//     // fn get_params(&self) -> Self::Params {
//     //     (self.e, self.rprime, self.v)
//     // }

//     // fn sign() -> Self {
//     //     CL03BlindSignature { e: 1, rprime: 2, v: 3 }
//     // }

// }

// impl BlindSignature for BBSplusBlindSignature {
//     type SignatureType = Self;
//     // type Params = (u32, u64, u32);
//     // fn get_params(&self) -> Self::Params {
//     //     (self.a, self.e, self.s)
//     // }

// }


// #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
// pub struct BlindSignatureGen<S: Scheme>{
//     _p: PhantomData<S>,
//     pub signature: BlindSignature<S>
// }

// impl <CS: BbsCiphersuite> BlindSignatureGen<BBSplus<CS>> {
//     pub fn prova() -> Self{
//         let s = BBSplusBlindSignature{ a: 1, e: 2, s: 3 };
//         Self{_p: PhantomData, signature: BlindSignature::BBSplus(s)}
//     }
// }

// impl <CS: CLCiphersuite> BlindSignatureGen<CL03<CS>> {
//     pub fn prova2() -> Self{
//         let s = CL03BlindSignature{e: 4, rprime: 5, v: 6};
//         Self{_p: PhantomData, signature: BlindSignature::CL03(s)}
//     }
// }




// pub trait BlindSignature {
//     type Parameters;

//     fn get_parameters(&self) -> Self::Parameters;
// }

// #[derive(Debug)]
// pub struct BBSplusParameters {
//     pub a: u32,
//     pub e: u64,
//     pub s: u32,
// }

// #[derive(Debug)]
// pub struct CL03Parameters {
//     pub e: u8,
//     pub rprime: u8,
//     pub v: u8,
// }

// #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
// pub struct BBSplusBlindSignature {
//     pub(crate) a: u32,
//     pub(crate) e: u64,
//     pub(crate) s: u32,
// }

// #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
// pub struct CL03BlindSignature {
//     pub(crate) e: u8,
//     pub(crate) rprime: u8,
//     pub(crate) v: u8,
// }

// impl BlindSignature for BBSplusBlindSignature {
//     type Parameters = BBSplusParameters;

//     fn get_parameters(&self) -> BBSplusParameters {
//         BBSplusParameters {
//             a: self.a,
//             e: self.e,
//             s: self.s,
//         }
//     }
// }

// impl BlindSignature for CL03BlindSignature {
//     type Parameters = CL03Parameters;

//     fn get_parameters(&self) -> CL03Parameters {
//         CL03Parameters {
//             e: self.e,
//             rprime: self.rprime,
//             v: self.v,
//         }
//     }
// }

// pub fn test<T: BlindSignature>(signature: T) -> T::Parameters {
//     signature.get_parameters()
// }
