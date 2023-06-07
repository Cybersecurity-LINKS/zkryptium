use std::{marker::{PhantomData}, borrow::Borrow};

use bls12_381_plus::{G1Projective, Scalar, G1Affine};
use elliptic_curve::{group::Curve, subtle::{CtOption, Choice}};
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::{ciphersuites::BbsCiphersuite, message::CL03Message}, cl03::ciphersuites::CLCiphersuite, keys::cl03_key::{CL03PublicKey, CL03SecretKey}, utils::random::{random_prime, random_bits}};

use super::{commitment::{CL03Commitment, self, Commitment}, signature::CL03Signature};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusBlindSignature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03BlindSignature {
    pub(crate) e: Integer,
    pub(crate) rprime: Integer,
    pub(crate) v: Integer,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BlindSignature<S: Scheme> {
    BBSplus(BBSplusBlindSignature),
    CL03(CL03BlindSignature),
    _Unreachable(std::marker::PhantomData<S>)
}

impl <CS:BbsCiphersuite> BlindSignature<BBSplus<CS>> {

    pub fn a(&self) -> G1Projective {
        match self {
            Self::BBSplus(inner) => inner.a,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn e(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.e,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn s(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.s,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> [u8; 112] {
        let mut bytes = [0u8; 112];
        bytes[0..48].copy_from_slice(&self.a().to_affine().to_compressed());
        let mut e = self.e().to_bytes();
        e.reverse();
        bytes[48..80].copy_from_slice(&e[..]);
        let mut s = self.s().to_bytes();
        s.reverse();
        bytes[80..112].copy_from_slice(&s[..]);
        bytes
    }

    pub fn from_bytes(data: &[u8; 112]) -> CtOption<Self> {
        let aa = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[0..48]).unwrap())
            .map(G1Projective::from);
        let mut e_bytes = <[u8; 32]>::try_from(&data[48..80]).unwrap();
        e_bytes.reverse();
        let ee = Scalar::from_bytes(&e_bytes);
        let mut s_bytes = <[u8; 32]>::try_from(&data[80..112]).unwrap();
        s_bytes.reverse();
        let ss = Scalar::from_bytes(&s_bytes);

        aa.and_then(|a| {
            ee.and_then(|e| ss.and_then(|s| CtOption::new(Self::BBSplus(BBSplusBlindSignature{ a, e, s }), Choice::from(1))))
        })
    }

}

impl <CS:CLCiphersuite> BlindSignature<CL03<CS>> {

    pub fn e(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.e,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn rprime(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.rprime,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn v(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.v,
            _ => panic!("Cannot happen!"),
        }
    }

    //TODO: ("remove the indexes");

    pub fn blind_sign(pk: &CL03PublicKey, sk: &CL03SecretKey, commitment: &Commitment<CL03<CS>>) -> Self{

        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        while ((&e > &Integer::from(Integer::from(2).pow(CS::le-1))) && (&e < &Integer::from(Integer::from(2).pow(CS::le))) && (Integer::from(e.gcd_ref(&phi_n)) == 1)) == false {
            e = random_prime(CS::le.try_into().unwrap());
        }

        let rprime = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());

        // v = powmod(((Cx) * powmod(pk['b'], rprime, pk['N']) * pk['c']), e2n, pk['N'])
        let v = ((commitment.value() * Integer::from(pk.b.pow_mod_ref(&rprime, &pk.N).unwrap())) * &pk.c).pow_mod(&e2n, &pk.N).unwrap();
        let sig = CL03BlindSignature{e, rprime, v};
        // sig = { 'e':e, 'rprime':rprime, 'v':v }

        Self::CL03(sig)

    }

    pub fn unblind_sing(&self, commitment: &Commitment<CL03<CS>>) -> CL03Signature {
        let s = commitment.randomness().clone() + self.rprime();
        CL03Signature { e: self.e().clone(), s: s, v: self.v().clone()}
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
