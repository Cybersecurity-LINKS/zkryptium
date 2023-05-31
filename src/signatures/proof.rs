use std::marker::PhantomData;

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::ciphersuites::BbsCiphersuite, cl03::ciphersuites::CLCiphersuite};



pub struct BBSplusPoKSignature{

}

pub struct CL03PoKSignature{

}


pub enum PoKSignature<S: Scheme>{
    BBSplus(BBSplusPoKSignature),
    CL03(CL03PoKSignature),
    _Unreachable(PhantomData<S>)
}


impl <CS: BbsCiphersuite> PoKSignature<BBSplus<CS>> {

}

impl <CS: CLCiphersuite> PoKSignature<CL03<CS>> {
    
}