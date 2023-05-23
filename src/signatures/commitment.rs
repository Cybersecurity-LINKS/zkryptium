use std::{ops::Index, marker::PhantomData, borrow::Borrow};

use bls12_381_plus::{Scalar, G1Projective, G1Affine};
use elliptic_curve::{group::GroupEncoding, hash2curve::ExpandMsg};
use rug::{Integer, integer::Order};
use serde::{Deserialize, Serialize};

use crate::{bbsplus::{message::{Message, self, BBSplusMessage}, ciphersuites::BbsCiphersuite, generators::{self, Generators, make_generators, global_generators}}, schemes::algorithms::{Scheme, BBSplus, CL03}, cl03::ciphersuites::CLCiphersuite, utils::util::{calculate_random_scalars, subgroup_check_g1}, keys::cl03_key::CL03PublicKey};


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


// impl BBSplusCommitment {
//     fn from_commitment<S: Scheme>(commitment: Commitment<S>) -> Self{
//         let mut encoding = <G1Projective as GroupEncoding>::Repr::default();
//         encoding.as_mut().copy_from_slice(commitment.value.as_slice());
        
//         let value = G1Projective::from_bytes(&encoding).unwrap();
//         let randomness = Scalar::from_bytes(commitment.randomness.as_slice().try_into().unwrap()).unwrap();

//         Self{value, randomness}
//     }
// }

// pub struct Commitment<S: Scheme> {
//     value: Vec<u8>,
//     randomness: Vec<u8>,
//     _p: PhantomData<S>
// }


// impl <CS: BbsCiphersuite> Commitment<BBSplus<CS>> 
// where
//     CS::Expander: for<'a> ExpandMsg<'a>,
// {
//     pub fn commit<M>(messages: &[M], generators: Option<&Generators>, unrevealed_message_indexes: &[usize]) -> Self
//     where
//         M: Message<Value = Scalar>
//     {
//         Self::preBlindSign(messages, generators, unrevealed_message_indexes)
//     }

//     fn preBlindSign<M>(messages: &[M], generators: Option<&Generators>, unrevealed_message_indexes: &[usize]) -> Self
//     where
//         M: Message<Value = Scalar>
//     {
//         let s_prime = calculate_random_scalars(1);

//         if unrevealed_message_indexes.is_empty() {
//             panic!("Unrevealed message indexes empty");
//         }

//         let get_generators_fn = make_generators::<CS>;

//         let mut gens: Generators;
//         if(generators.is_none()){
//             gens = global_generators(get_generators_fn, unrevealed_message_indexes.iter().max().unwrap()+3).to_owned().clone();
//         }
//         else {
//             gens = generators.unwrap().clone();
//         }
        
//         // let generators = generators.unwrap_or_else(|| { &global_generators(get_generators_fn, unrevealed_message_indexes.iter().max().unwrap()+3)}).clone();

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
        
//         Self{value: commitment.to_bytes().as_ref().to_vec(), randomness: s_prime[0].to_bytes().to_vec(), _p: PhantomData }

//     }

// }

// impl <CS: CLCiphersuite> Commitment<CL03<CS>> {
//     pub fn commit<M: Message>(messages: &[M]) {

//     }

//     pub fn to_integer(&self) -> Integer {
//         Integer::from_digits(&self.value, Order::Lsf)
//     }
// }

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusCommitmentContext<S: Scheme>{
    messages: Vec<BBSplusMessage>,
    generators: Option<Generators>,
    unrevealed_message_indexes: Vec<usize>,
    _p: PhantomData<S>
}

impl <CS: BbsCiphersuite> BBSplusCommitmentContext<BBSplus<CS>> {
    pub fn new(messages: &[BBSplusMessage], generators: Option<&Generators>, unrevealed_message_indexes: &[usize]) -> Self{
        Self{messages: messages.to_vec(), generators: generators.cloned(), unrevealed_message_indexes: unrevealed_message_indexes.to_vec(), _p: PhantomData }
    }

    fn preBlindSign(&self) -> BBSplusCommitment
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        
        let messages = self.messages.as_slice();
        let s_prime = calculate_random_scalars(1);

        let unrevealed_message_indexes = self.unrevealed_message_indexes.as_slice();
        let generators = self.generators.as_ref();

        if unrevealed_message_indexes.is_empty() {
                        panic!("Unrevealed message indexes empty");
                    }

        let get_generators_fn = make_generators::<CS>;

        let mut gens: Generators;
        if(generators.is_none()){
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
        
        BBSplusCommitment{value: commitment, randomness: s_prime[0] }

    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03CommitmentContex {
    messages: Vec<BBSplusMessage>,
    pk: CL03PublicKey,
    unrevealed_message_indexes: Vec<usize>
}



pub trait CommitmentContext{
    type Commitment: Commitment<Value = Self::Value, Randomness = Self::Randomness>;
    type Value;
    type Randomness;
    fn commit(&self)-> Self::Commitment;
}

impl <CS: BbsCiphersuite> CommitmentContext for BBSplusCommitmentContext<BBSplus<CS>>
where
    CS::Expander: for<'a> ExpandMsg<'a>,
{ 
    type Commitment = BBSplusCommitment;
    
    type Value = G1Projective;

    type Randomness = Scalar;

    fn commit(&self) -> Self::Commitment 
    {
        Self::preBlindSign(self)

    }

    
}

impl CommitmentContext for CL03CommitmentContex 
{
    type Commitment = CL03Commitment;

    type Value = Integer;

    type Randomness = Integer;

    fn commit(&self) -> CL03Commitment {
        todo!()
    }
}


pub trait Commitment{
    type Value;
    type Randomness;
    // fn commit(context: &Self::Context) -> Self::Output;
    fn value(&self) -> Self::Value;
    fn randomness(&self) -> Self::Randomness;
}

impl Commitment for BBSplusCommitment 
{
    type Value = G1Projective;
    type Randomness = Scalar;

    fn value(&self) -> Self::Value {
        self.value
    }

    fn randomness(&self) -> Self::Randomness {
        self.randomness
    }


}


impl Commitment for CL03Commitment {
    type Value = Integer;
    type Randomness = Integer;

    fn value(&self) -> Self::Value {
        todo!()
    }

    fn randomness(&self) -> Self::Randomness {
        todo!()
    }
}