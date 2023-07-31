
use std::error::Error;
use std::fmt;


#[derive(Debug)]
pub struct BlindSignError(pub String);

impl fmt::Display for BlindSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub struct ZKPoKError(pub String);

impl fmt::Display for ZKPoKError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for BlindSignError {}
impl Error for ZKPoKError{}
