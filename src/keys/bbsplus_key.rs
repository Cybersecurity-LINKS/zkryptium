// use super::key::Private;
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BBSplusPublicKey{

}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BBSplusSecretKey{
    
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BBSplusKeyPair{
    private: BBSplusSecretKey,
    public: BBSplusPublicKey
}

impl BBSplusKeyPair {
    pub fn new(private: BBSplusSecretKey, public: BBSplusPublicKey) -> Self {
        Self{private, public}
    }
}