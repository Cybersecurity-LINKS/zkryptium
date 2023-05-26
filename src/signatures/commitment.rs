use std::{ops::Index, marker::PhantomData, borrow::Borrow};

use bls12_381_plus::{Scalar, G1Projective, G1Affine};
use elliptic_curve::{group::GroupEncoding, hash2curve::ExpandMsg};
use rug::{Integer, integer::Order};
use serde::{Deserialize, Serialize};

use crate::{bbsplus::{message::{Message, self, BBSplusMessage}, ciphersuites::BbsCiphersuite, generators::{self, Generators, make_generators, global_generators}}, schemes::algorithms::{Scheme, BBSplus, CL03, Ciphersuite}, cl03::ciphersuites::CLCiphersuite, utils::util::{calculate_random_scalars, subgroup_check_g1}, keys::cl03_key::CL03PublicKey};


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Commitment {
    pub value: Integer,
    pub randomness: Integer
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusCommitment {
    pub value: G1Projective,
    pub randomness: Scalar
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Commitment<S: Scheme> {
    BBSplus(BBSplusCommitment),
    CL03(CL03Commitment),
    _Unreachable(std::marker::PhantomData<S>)
}

impl <CS: BbsCiphersuite> Commitment<BBSplus<CS>> {

    pub fn commit(messages: &[BBSplusMessage], generators: Option<&Generators>, unrevealed_message_indexes: &[usize]) -> Self
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {

        let s_prime = calculate_random_scalars(1);

        if unrevealed_message_indexes.is_empty() {
                        panic!("Unrevealed message indexes empty");
                    }

        let get_generators_fn = make_generators::<CS>;

        let gens: Generators;
        if generators.is_none() {
            gens = global_generators(get_generators_fn, unrevealed_message_indexes.iter().max().unwrap()+3).to_owned().clone();
        }
        else {
            gens = generators.unwrap().clone();
        }


        if unrevealed_message_indexes.iter().max().unwrap() >= &gens.message_generators.len() {
            panic!("Non enought generators!");
        }

        if subgroup_check_g1(gens.g1_base_point) == false {
            panic!("Failed subgroup check");
        }

        for i in unrevealed_message_indexes {
            if subgroup_check_g1(gens.message_generators[*i]) == false {
                panic!("Failed subgroup check");
            }
        }

        let mut commitment = gens.g1_base_point * s_prime[0];

        let mut index: usize = 0;

        for i in unrevealed_message_indexes {
            // commitment = commitment + (gens.message_generators[*i] * Scalar::from_bytes(&messages[index].to_bytes()).unwrap());
            commitment = commitment + (gens.message_generators[*i] * &messages[index].get_value());
        
            index = index + 1;
        }
        
        Self::BBSplus(BBSplusCommitment{value: commitment, randomness: s_prime[0]})

    }

    pub fn value(&self) -> &G1Projective {
        match self {
            Self::BBSplus(inner) => &inner.value,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn randomness(&self) -> &Scalar {
        match self {
            Self::BBSplus(inner) => &inner.randomness,
            _ => panic!("Cannot happen!")
        }
    }
}


impl <CS: CLCiphersuite> Commitment<CL03<CS>> {
    pub fn commit() -> Self {
        todo!()
    }

    pub fn value(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.value,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn randomness(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.randomness,
            _ => panic!("Cannot happen!")
        }
    }
}


// #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
// pub struct BBSplusCommitmentContext<S: Scheme>{
//     messages: Vec<BBSplusMessage>,
//     generators: Option<Generators>,
//     unrevealed_message_indexes: Vec<usize>,
//     _p: PhantomData<S>
// }

// impl <CS: BbsCiphersuite> BBSplusCommitmentContext<BBSplus<CS>> {
//     pub fn new(messages: &[BBSplusMessage], generators: Option<&Generators>, unrevealed_message_indexes: &[usize]) -> Self{
//         Self{messages: messages.to_vec(), generators: generators.cloned(), unrevealed_message_indexes: unrevealed_message_indexes.to_vec(), _p: PhantomData }
//     }

//     fn preBlindSign(&self) -> BBSplusCommitment
//     where
//         CS::Expander: for<'a> ExpandMsg<'a>,
//     {
        
//         let messages = self.messages.as_slice();
//         let s_prime = calculate_random_scalars(1);

//         let unrevealed_message_indexes = self.unrevealed_message_indexes.as_slice();
//         let generators = self.generators.as_ref();

//         if unrevealed_message_indexes.is_empty() {
//                         panic!("Unrevealed message indexes empty");
//                     }

//         let get_generators_fn = make_generators::<CS>;

//         let mut gens: Generators;
//         if(generators.is_none()){
//             gens = global_generators(get_generators_fn, unrevealed_message_indexes.iter().max().unwrap()+3).to_owned().clone();
//         }
//         else {
//             gens = generators.unwrap().clone();
//         }


//         if unrevealed_message_indexes.iter().max().unwrap() >= &gens.message_generators.len() {
//             panic!("Non enought generators!");
//         }

//         if subgroup_check_g1(gens.g1_base_point) == false {
//             panic!("Failed subgroup check");
//         }

//         for i in unrevealed_message_indexes {
//             if subgroup_check_g1(gens.message_generators[*i]) == false {
//                 panic!("Failed subgroup check");
//             }
//         }

//         let mut commitment = gens.g1_base_point * s_prime[0];

//         let mut index: usize = 0;

//         for i in unrevealed_message_indexes {
//             // commitment = commitment + (gens.message_generators[*i] * Scalar::from_bytes(&messages[index].to_bytes()).unwrap());
//             commitment = commitment + (gens.message_generators[*i] * &messages[index].get_value());
        
//             index = index + 1;
//         }
        
//         BBSplusCommitment{value: commitment, randomness: s_prime[0] }

//     }
// }

// #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
// pub struct CL03CommitmentContex {
//     messages: Vec<BBSplusMessage>,
//     pk: CL03PublicKey,
//     unrevealed_message_indexes: Vec<usize>
// }



// pub trait CommitmentContext{
//     type Commitment: Commitment<Value = Self::Value, Randomness = Self::Randomness>;
//     type Value;
//     type Randomness;
//     fn commit(&self)-> Self::Commitment;
// }

// impl <CS: BbsCiphersuite> CommitmentContext for BBSplusCommitmentContext<BBSplus<CS>>
// where
//     CS::Expander: for<'a> ExpandMsg<'a>,
// { 
//     type Commitment = BBSplusCommitment;
    
//     type Value = G1Projective;

//     type Randomness = Scalar;

//     fn commit(&self) -> Self::Commitment 
//     {
//         Self::preBlindSign(self)

//     }

    
// }

// impl CommitmentContext for CL03CommitmentContex 
// {
//     type Commitment = CL03Commitment;

//     type Value = Integer;

//     type Randomness = Integer;

//     fn commit(&self) -> CL03Commitment {
//         todo!()
//     }
// }


// pub trait Commitment{
//     type Value;
//     type Randomness;
//     // fn commit(context: &Self::Context) -> Self::Output;
//     fn value(&self) -> Self::Value;
//     fn randomness(&self) -> Self::Randomness;
// }

// impl Commitment for BBSplusCommitment 
// {
//     type Value = G1Projective;
//     type Randomness = Scalar;

//     fn value(&self) -> Self::Value {
//         self.value
//     }

//     fn randomness(&self) -> Self::Randomness {
//         self.randomness
//     }


// }


// impl Commitment for CL03Commitment {
//     type Value = Integer;
//     type Randomness = Integer;

//     fn value(&self) -> Self::Value {
//         todo!()
//     }

//     fn randomness(&self) -> Self::Randomness {
//         todo!()
//     }
// }







