/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

//TODO: (open issue) use this struct to represent the commitment HashCommitment{comm: BigInt, r: BigInt, m: BigInt}
/// calculate commitment c = H(m,r) using SHA3 CRHF.
/// r is 256bit blinding factor, m is the commited value
pub struct HashCommitment;
use curv::arithmetic::big_gmp::BigInt;

use super::traits::Commitment;
use super::SECURITY_BITS;
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::hashing::blake2b512::Blake;

//TODO:  using the function with BigInt's as input instead of string's makes it impossible to commit to empty message or use empty randomness
impl Commitment<BigInt> for HashCommitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> BigInt {
        Blake::create_hash(&vec![message, &blinding_factor], b"Zcash_RedJubjubH")
    }

    fn create_commitment(message: &BigInt) -> (BigInt, BigInt) {
        let blinding_factor = BigInt::sample(SECURITY_BITS);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            message,
            &blinding_factor,
        );
        (com, blinding_factor)
    }
}
