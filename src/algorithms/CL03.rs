use crate::signatures::signature::Sign;


struct CL03;

impl Sign for CL03 {
    type Private;

    type Output = [u8 ; ];

    fn sign(message: &[u8], key: &Self::Private) -> Self::Output {
        todo!()
    }
}