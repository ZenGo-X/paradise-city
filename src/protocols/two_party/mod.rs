#![allow(non_snake_case)]
/*
    paradise-city

    Copyright 2018 by Kzen Networks

    This file is part of paradise-city library
    (https://github.com/KZen-networks/paradise-city)

    paradise-city is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/paradise-city/blob/master/LICENSE>
*/

use Error::{self, InvalidSig};
pub mod party_one;
pub mod party_two;
pub mod test;

use curv::arithmetic::big_gmp::BigInt;
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::blake2b512::Blake;
use curv::elliptic::curves::curve_jubjub::FE;
use curv::elliptic::curves::curve_jubjub::GE;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub ak: GE,
    pub ask: FE,
}

#[derive(Clone, Debug)]
pub struct EphemeralKey {
    pub message: BigInt,
    pub vk: GE,
    pub R: GE,
}

#[derive(Clone, Debug)]
pub struct EphEcKeyPair {
    pub R_i: GE,
    r_i: FE,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub s: FE,
    pub R: GE,
}

pub fn compute_ak(local_share: &EcKeyPair, ak_counter_party: &GE) -> GE {
    ak_counter_party + &local_share.ak
}

pub fn compute_vk(ak: &GE, alpha: &FE) -> GE {
    let G = GE::generator();
    ak + &(G * alpha)
}

pub fn compute_R(local_share: &EphEcKeyPair, R_counter_party: &GE) -> GE {
    R_counter_party + &local_share.R_i
}

pub fn verify(vk: GE, message: &BigInt, sig: &Signature) -> Result<(), Error> {
    let mut R_vec = BigInt::to_vec(&sig.R.bytes_compressed_to_big_int());
    R_vec.reverse();
    let R_bn = BigInt::from(&R_vec[..]);
    let c = Blake::create_hash(&vec![&R_bn, message], b"Zcash_RedJubjubH");
    let mut c_vec = BigInt::to_vec(&c);
    c_vec.reverse();
    let c = BigInt::from(&c_vec[..]);

    let c_fe: FE = ECScalar::from(&c);
    let R_plus_cvk = sig.R + vk * &c_fe;
    let G = GE::generator();
    let sG = G * &sig.s;
    match sG == R_plus_cvk {
        true => Ok(()),
        false => Err(InvalidSig),
    }
}
