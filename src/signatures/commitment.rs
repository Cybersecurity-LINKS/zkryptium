use bls12_381_plus::{Scalar, G1Projective};
use elliptic_curve::{hash2curve::ExpandMsg};
use rug::{Integer};
use serde::{Deserialize, Serialize};

use crate::{bbsplus::{message::{Message, BBSplusMessage, CL03Message}, ciphersuites::BbsCiphersuite, generators::{Generators, make_generators, global_generators}}, schemes::algorithms::{Scheme, BBSplus, CL03}, cl03::ciphersuites::CLCiphersuite, utils::{util::{calculate_random_scalars, subgroup_check_g1}, random::random_bits}, keys::{cl03_key::{CL03PublicKey, CL03CommitmentPublicKey}}};


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Commitment {
    pub value: Integer,
    pub randomness: Integer
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusCommitment {
    pub value: G1Projective,
    pub s_prime: Scalar
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

        let s_prime = calculate_random_scalars::<CS>(1, None);

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

        let mut commitment = gens.q1 * s_prime[0];

        // let mut index: usize = 0;

        for i in unrevealed_message_indexes {
            // commitment = commitment + (gens.message_generators[*i] * Scalar::from_bytes(&messages[index].to_bytes()).unwrap());
            commitment += gens.message_generators.get(*i).expect("index overflow") * &messages.get(*i).expect("Index overflow").get_value();
        
            // index = index + 1;
        }
        
        Self::BBSplus(BBSplusCommitment{value: commitment, s_prime: s_prime[0]})

    }

    pub fn value(&self) -> &G1Projective {
        match self {
            Self::BBSplus(inner) => &inner.value,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn bbsPlusCommitment(&self) -> &BBSplusCommitment {
        match self {
            Self::BBSplus(inner) => &inner,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn s_prime(&self) -> &Scalar {
        match self {
            Self::BBSplus(inner) => &inner.s_prime,
            _ => panic!("Cannot happen!")
        }
    }
}


impl <CS: CLCiphersuite> Commitment<CL03<CS>> {
    pub(crate) fn commit_v(v: &Integer, commitment_pk: &CL03CommitmentPublicKey) -> Self {
        let w = random_bits(CS::ln);

        let Cv = (v * Integer::from(commitment_pk.g_bases[0].pow_mod_ref(&w, &commitment_pk.N).unwrap())) % &commitment_pk.N;

        Self::CL03(CL03Commitment { value: Cv, randomness: w })
    }

    pub fn commit_with_pk(messages: &[CL03Message], pk: &CL03PublicKey, unrevealed_message_indexes: Option<&[usize]>) -> Self {
        let unrevealed_message_indexes: Vec<usize> = match unrevealed_message_indexes {
            Some(indexes) => indexes.to_vec(),
            None => (0..messages.len()).collect(),
        };

        let r = random_bits(CS::ln);
        let mut Cx = Integer::from(1);

        for i in unrevealed_message_indexes {
            let ai = pk.a_bases.get(i).and_then(|a| {return Some(a);}).expect("Invalid unrevealed message index!");
            let mi = &messages[i];
            Cx = Cx * Integer::from(ai.pow_mod_ref(&mi.get_value(), &pk.N).unwrap());
        }

        Cx = (Cx * Integer::from(pk.b.pow_mod_ref(&r, &pk.N).unwrap())) % &pk.N;

        Self::CL03(CL03Commitment { value: Cx, randomness: r })
    }

    pub fn commit_with_commitment_pk(messages: &[CL03Message], commitment_pk: &CL03CommitmentPublicKey, unrevealed_message_indexes: Option<&[usize]>) -> Self {
        let unrevealed_message_indexes: Vec<usize> = match unrevealed_message_indexes {
            Some(indexes) => indexes.to_vec(),
            None => (0..messages.len()).collect(),
        };
        
        let r = random_bits(CS::ln);
        let mut Cx = Integer::from(1);

        for i in unrevealed_message_indexes {
            let ai = commitment_pk.g_bases.get(i).and_then(|a| {return Some(a);}).expect("Invalid unrevealed message index!");
            let mi = &messages[i];
            Cx = Cx * Integer::from(ai.pow_mod_ref(&mi.get_value(), &commitment_pk.N).unwrap());
        }

        Cx = (Cx * Integer::from(commitment_pk.h.pow_mod_ref(&r, &commitment_pk.N).unwrap())) % &commitment_pk.N;

        Self::CL03(CL03Commitment { value: Cx, randomness: r })
    }

    pub fn extend_commitment_with_pk(&mut self, revealed_messages: &[CL03Message], pk: &CL03PublicKey, revealed_message_indexes: Option<&[usize]>) {
        // let mut extended_Cx = self.value().clone();
        let revealed_message_indexes: Vec<usize> = match revealed_message_indexes {
            Some(indexes) => indexes.to_vec(),
            None => (0..revealed_messages.len()).collect(),
        };

        if revealed_message_indexes.len() != revealed_messages.len() {
            panic!("Number of revealed messages not corresponds to the number of revelead message indexes!");
        }

        let extended_Cx = self.cl03Commitment_mut();
        let mut extended_Cx_value = extended_Cx.value.clone();
        let mut index = 0usize; 
        for i in revealed_message_indexes {
            let ai = pk.a_bases.get(i).and_then(|a| {return Some(a);}).expect("Invalid revealed message index!");
            let mi = &revealed_messages.get(index).expect("Index overflow");
            extended_Cx_value = (extended_Cx_value * Integer::from(ai.pow_mod_ref(&mi.get_value(), &pk.N).unwrap())) % &pk.N;
            index += 1;
        }

        extended_Cx.value = extended_Cx_value;
        // self.set_value(extended_Cx);
    }


    //TODO: Forse da cambiare (messages sono revealed_messages e non tutti i messages)
    pub fn extend_commitment_with_commitment_pk(&mut self, messages: &[CL03Message], commitment_pk: &CL03CommitmentPublicKey, revealed_message_indexes: Option<&[usize]>) {
        // let mut extended_Cx = self.value().clone();
        let revealed_message_indexes: Vec<usize> = match revealed_message_indexes {
            Some(indexes) => indexes.to_vec(),
            None => (0..messages.len()).collect(),
        };
        let extended_Cx = self.cl03Commitment_mut();
        let mut extended_Cx_value = extended_Cx.value.clone();
        for i in revealed_message_indexes {
            let ai = commitment_pk.g_bases.get(i).and_then(|a| {return Some(a);}).expect("Invalid revealed message index!");
            let mi = &messages[i];
            extended_Cx_value = (extended_Cx_value * Integer::from(ai.pow_mod_ref(&mi.get_value(), &commitment_pk.N).unwrap())) % &commitment_pk.N;
        }

        extended_Cx.value = extended_Cx_value;
        // self.set_value(extended_Cx);
    }


    pub fn value(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.value,
            _ => panic!("Cannot happen!")
        }
    }

    // pub fn set_value(&mut self, value: Integer) {
    //     match self {
    //         Self::CL03(inner) => inner.value = value,
    //         _ => panic!("Cannot happen!")
    //     }
    // }

    pub fn cl03Commitment_mut(&mut self) -> &mut CL03Commitment {
        match self {
            Self::CL03(ref mut inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn cl03Commitment(&self) -> &CL03Commitment {
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!"),
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







