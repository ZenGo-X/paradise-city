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

use super::party_two::CoinFlipFirstMsg as Party2CoinFlipFirstMsg;
use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMsg;
use super::party_two::LocalSignatureMsg as CounterLocalSig;
use super::{EcKeyPair, EphEcKeyPair};
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::blake2b512::Blake;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::ProveDLog;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHStatement;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHWitness;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::NISigmaProof;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use protocols::two_party::verify;
use protocols::two_party::Signature;

const SECURITY_BITS: usize = 256;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {
    pub comm_witness: CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinFlipFirstMsg {
    pub cf_msg1: coin_flip_optimal_rounds::Party1FirstMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinFlipSecondMsg {
    pub cf_msg2: coin_flip_optimal_rounds::Party1SecondMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {
    pub comm_witness: EphCommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphCommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: ECDDHProof,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignatureMsg {
    pub s1: FE,
}

impl KeyGenFirstMsg {
    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base: GE = ECPoint::generator();

        let secret_share: FE = ECScalar::new_random();
        //in Lindell's protocol range proof works only for x1<q/3
        let secret_share: FE =
            ECScalar::from(&secret_share.to_big_int().div_floor(&BigInt::from(3)));

        let public_share = base.scalar_mul(&secret_share.get_element());

        let d_log_proof = DLogProof::prove(&secret_share);
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );
        let ec_key_pair = EcKeyPair {
            ak: public_share,
            ask: secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.ak.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }

    pub fn create_commitments_with_fixed_secret_share(
        secret_share: FE,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        //in Lindell's protocol range proof works only for x1<q/3
        let sk_bigint = secret_share.to_big_int();
        let q_third = FE::q();
        assert!(&sk_bigint < &q_third.div_floor(&BigInt::from(3)));
        let base: GE = ECPoint::generator();
        let public_share = base.scalar_mul(&secret_share.get_element());

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = EcKeyPair {
            ak: public_share,
            ask: secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.ak.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: CommWitness,
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

impl CoinFlipFirstMsg {
    pub fn commit() -> (CoinFlipFirstMsg, FE, FE) {
        let (cf_msg1, seed, blinding) = coin_flip_optimal_rounds::Party1FirstMessage::commit();
        (CoinFlipFirstMsg { cf_msg1 }, seed, blinding)
    }
}

impl CoinFlipSecondMsg {
    pub fn reveal(
        party2_first_message: &Party2CoinFlipFirstMsg,
        seed: FE,
        blinding: FE,
    ) -> (CoinFlipSecondMsg, FE) {
        let (cf_msg2, coin_flip) = coin_flip_optimal_rounds::Party1SecondMessage::reveal(
            &party2_first_message.cf_msg1.seed,
            &seed,
            &blinding,
        );

        (CoinFlipSecondMsg { cf_msg2 }, coin_flip)
    }
}

impl EphKeyGenFirstMsg {
    pub fn create_commitments(
        vk: &GE,
        message: &BigInt,
    ) -> (EphKeyGenFirstMsg, EphCommWitness, EphEcKeyPair) {
        let base: GE = ECPoint::generator();

        let randomness: FE = ECScalar::new_random();
        let ft = HSha256::create_hash(&vec![
            &vk.bytes_compressed_to_big_int(),
            message,
            &randomness.to_big_int(),
        ]);
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

        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &R_i.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &HSha256::create_hash_from_ge(&[&d_log_proof.a1, &d_log_proof.a2]).to_big_int(),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = EphEcKeyPair { R_i, r_i };
        (
            EphKeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            EphCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.R_i.clone(),
                d_log_proof,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: EphCommWitness,
        party_one_first_message: &Party2EphKeyGenFirstMsg,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: party_one_first_message.public_share.clone(),
            g2: GE::base_point2(),
            h2: party_one_first_message.c.clone(),
        };
        party_one_first_message.d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg { comm_witness })
    }
}

impl LocalSignatureMsg {
    pub fn compute_s1(
        R: &GE,
        vk: &GE,
        key: EcKeyPair,
        eph_key: EphEcKeyPair,
        message: &BigInt,
        alpha: &FE,
    ) -> LocalSignatureMsg {
        let hash_R_vk_m = Blake::create_hash(
            &vec![
                &R.bytes_compressed_to_big_int(),
                &vk.bytes_compressed_to_big_int(),
                message,
            ],
            b"Zcash_RedJubjubH",
        );
        let hash_fe: FE = ECScalar::from(&hash_R_vk_m);
        let s1 = eph_key.r_i + hash_fe * (key.ask + alpha);
        LocalSignatureMsg { s1 }
    }

    pub fn compute(
        R: GE,
        vk: GE,
        local_sig: &LocalSignatureMsg,
        counter_sig: &CounterLocalSig,
        message: &BigInt,
    ) -> Signature {
        let sig = Signature {
            s: local_sig.s1 + counter_sig.s2,
            R,
        };
        verify(vk, message, &sig).expect("bad signature");
        sig
    }
}
