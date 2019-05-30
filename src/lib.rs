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

#[macro_use]
extern crate serde_derive;
extern crate blake2_rfc;
extern crate serde;
extern crate serde_json;
extern crate subtle;
extern crate zeroize;
pub mod curv;
pub mod protocols;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}

pub enum ErrorSS {
    VerifyShareError,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}
