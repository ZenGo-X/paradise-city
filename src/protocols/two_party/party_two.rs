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

use super::party_one::CoinFlipFirstMsg as Party1CoinFlipFirstMsg;
use super::party_one::CoinFlipSecondMsg as Party1CoinFlipSecondMsg;
use super::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMessage;
use super::party_one::EphKeyGenSecondMsg as Party1EphKeyGenSecondMessage;
use super::party_one::KeyGenFirstMsg as Party1KeyGenFirstMessage;
use super::party_one::KeyGenSecondMsg as Party1KeyGenSecondMessage;
use super::party_one::LocalSignatureMsg as CounterLocalSig;
use super::{EcKeyPair, EphEcKeyPair};
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::blake2b512::Blake;

use curv::arithmetic::big_gmp::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::ProveDLog;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHStatement;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHWitness;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::NISigmaProof;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use curv::elliptic::curves::curve_jubjub::FE;
use curv::elliptic::curves::curve_jubjub::GE;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use protocols::two_party::verify;
use protocols::two_party::Signature;
use curv::arithmetic::traits::Converter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinFlipFirstMsg {
    pub cf_msg1: coin_flip_optimal_rounds::Party2FirstMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinFlipResult {
    pub party2_alpha: FE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub d_log_proof: ECDDHProof,
    pub public_share: GE,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignatureMsg {
    pub s2: FE,
}

impl KeyGenFirstMsg {
    pub fn create() -> (KeyGenFirstMsg, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            ak: public_share,
            ask: secret_share,
        };
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn create_with_fixed_secret_share(secret_share: FE) -> (KeyGenFirstMsg, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            ak: public_share,
            ask: secret_share,
        };
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_one_first_message: &Party1KeyGenFirstMessage,
        party_one_second_message: &Party1KeyGenSecondMessage,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let party_one_pk_commitment = &party_one_first_message.pk_commitment;
        let party_one_zk_pok_commitment = &party_one_first_message.zk_pok_commitment;
        let party_one_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_one_public_share = &party_one_second_message.comm_witness.public_share;
        let party_one_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_one_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;

        let mut flag = true;
        match party_one_pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.bytes_compressed_to_big_int(),
                &party_one_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof
                    .pk_t_rand_commitment
                    .bytes_compressed_to_big_int(),
                &party_one_zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(&party_one_d_log_proof)?;
        Ok(KeyGenSecondMsg {})
    }
}

impl CoinFlipFirstMsg {
    pub fn share(party1_first_message: &Party1CoinFlipFirstMsg) -> (CoinFlipFirstMsg) {
        CoinFlipFirstMsg {
            cf_msg1: coin_flip_optimal_rounds::Party2FirstMessage::share(
                &party1_first_message.cf_msg1.proof,
            ),
        }
    }
}

impl CoinFlipResult {
    pub fn finalize(
        party1_second_message: &Party1CoinFlipSecondMsg,
        party2_first_message: &CoinFlipFirstMsg,
        party1_first_message: &Party1CoinFlipFirstMsg,
    ) -> CoinFlipResult {
        let coin_flip = coin_flip_optimal_rounds::finalize(
            &party1_second_message.cf_msg2.proof,
            &party2_first_message.cf_msg1.seed,
            &party1_first_message.cf_msg1.proof.com,
        );
        CoinFlipResult {
            party2_alpha: coin_flip,
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create(vk: &GE, message: &BigInt) -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base: GE = ECPoint::generator();
        let randomness: FE = ECScalar::new_random();
        let ft = Blake::create_hash(
            &vec![
                &vk.bytes_compressed_to_big_int(),
                message,
                &randomness.to_big_int(),
            ],
            b"Zcash_RedJubjubH",
        );
        let r_i = ECScalar::from(&ft);
        let R_i = base * &r_i;

        let h: GE = GE::base_point2();
        let w = ECDDHWitness { x: r_i.clone() };
        let c = &h * &r_i;
        let delta = ECDDHStatement {
            g1: base.clone(),
            h1: R_i.clone(),
            g2: h.clone(),
            h2: c.clone(),
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);
        let ec_key_pair = EphEcKeyPair { R_i, r_i };
        (
            EphKeyGenFirstMsg {
                d_log_proof,
                public_share: R_i,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_one_first_message: &Party1EphKeyGenFirstMessage,
        party_one_second_message: &Party1EphKeyGenSecondMessage,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        let party_two_pk_commitment = &party_one_first_message.pk_commitment;
        let party_two_zk_pok_commitment = &party_one_first_message.zk_pok_commitment;
        let party_two_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_two_public_share = &party_one_second_message.comm_witness.public_share;
        let party_two_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_two_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;
        let mut flag = true;
        match party_two_pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_two_public_share.bytes_compressed_to_big_int(),
                &party_two_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_two_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &Blake::create_hash_from_ge(
                    &[&party_two_d_log_proof.a1, &party_two_d_log_proof.a2],
                    b"Zcash_RedJubjubH",
                )
                .to_big_int(),
                &party_two_zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: party_two_public_share.clone(),
            g2: GE::base_point2(),
            h2: party_one_second_message.comm_witness.c.clone(),
        };
        party_two_d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg {})
    }
}

impl LocalSignatureMsg {
    pub fn compute_s2(
        R: &GE,
        vk: &GE,
        key: EcKeyPair,
        eph_key: EphEcKeyPair,
        message: &BigInt,
    ) -> LocalSignatureMsg {

     //   let vk_m = ((vk.bytes_compressed_to_big_int()).shl(256)) + message;
        let mut R_vec = BigInt::to_vec(&R.bytes_compressed_to_big_int());
        R_vec.reverse();
        let R_bn = BigInt::from(&R_vec[..]);
        let hash_R_vk_m = Blake::create_hash(
            &vec![
                &R_bn,
                &message,
            ],
            b"Zcash_RedJubjubH",
        );
        let mut hash_R_vk_m_vec = BigInt::to_vec(&hash_R_vk_m);
        hash_R_vk_m_vec.reverse();
        let hash_R_vk_m = BigInt::from(&hash_R_vk_m_vec[..]);
        let hash_fe: FE = ECScalar::from(&hash_R_vk_m);
        let s2 = eph_key.r_i + hash_fe * key.ask;
        LocalSignatureMsg { s2 }
    }

    pub fn compute(
        R: GE,
        vk: GE,
        local_sig: &LocalSignatureMsg,
        counter_sig: &CounterLocalSig,
        message: &BigInt,
    ) -> Signature {
        let sig = Signature {
            s: local_sig.s2 + counter_sig.s1,
            R,
        };
        verify(vk, message, &sig).expect("bad signature");
        sig
    }
}
