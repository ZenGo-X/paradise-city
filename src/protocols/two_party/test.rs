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

//use protocols::two_party::

#[cfg(test)]
mod tests {
    use curv::arithmetic::big_gmp::BigInt;
    use curv::elliptic::curves::curve_jubjub::GE;
    use protocols::two_party::compute_R;
    use protocols::two_party::compute_ak;
    use protocols::two_party::compute_vk;
    use protocols::two_party::party_one::CoinFlipFirstMsg as Party1CFFirstMsg;
    use protocols::two_party::party_one::CoinFlipSecondMsg as Party1CFSecondMsg;
    use protocols::two_party::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
    use protocols::two_party::party_one::EphKeyGenSecondMsg as Party1EphKeyGenSecondMsg;
    use protocols::two_party::party_one::KeyGenFirstMsg as Party1KeyGenFirstMsg;
    use protocols::two_party::party_one::KeyGenSecondMsg as Party1KeyGenSecondMsg;
    use protocols::two_party::party_one::LocalSignatureMsg as Party1LocalSignatureMsg;
    use protocols::two_party::party_two::CoinFlipFirstMsg as Party2CFFirstMsg;
    use protocols::two_party::party_two::CoinFlipResult;
    use protocols::two_party::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMsg;
    use protocols::two_party::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMsg;
    use protocols::two_party::party_two::KeyGenFirstMsg as Party2KeyGenFirstMsg;
    use protocols::two_party::party_two::KeyGenSecondMsg as Party2KeyGenSecondMsg;
    use protocols::two_party::party_two::LocalSignatureMsg as Party2LocalSignatureMsg;
    use protocols::two_party::EcKeyPair;

    #[test]
    fn test_2p_keygen() {
        // round 1
        // party1:
        let (party1_first_message, comm_witness, party1_keys) =
            Party1KeyGenFirstMsg::create_commitments();
        // party2:
        let (party2_first_message, party2_keys) = Party2KeyGenFirstMsg::create();
        // round 2
        // party1
        let party1_second_message = Party1KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party2_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");
        // compute ak:
        let party1_ak = compute_ak(&party1_keys, &party2_first_message.public_share);
        // party2
        let _party_two_second_message = Party2KeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &party1_first_message,
            &party1_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
        let party2_ak = compute_ak(
            &party2_keys,
            &party1_second_message.comm_witness.public_share,
        );

        assert_eq!(party1_ak, party2_ak);
    }

    #[test]
    fn test_2p_sign() {
        let (party1_keys, party2_keys, public_key) = two_party_keygen();
        let message = BigInt::from(10);
        // round 1
        // party1
        let (party1_cf_first_message, party1_cf_seed, party1_cf_blinding) =
            Party1CFFirstMsg::commit();
        // party2
        let party2_cf_first_message = Party2CFFirstMsg::share(&party1_cf_first_message);
        // round 2
        // party1
        let (party1_cf_second_message, party1_alpha) =
            Party1CFSecondMsg::reveal(&party2_cf_first_message, party1_cf_seed, party1_cf_blinding);
        let party1_vk = compute_vk(&public_key, &party1_alpha);
        // party2
        let coin_flip_res = CoinFlipResult::finalize(
            &party1_cf_second_message,
            &party2_cf_first_message,
            &party1_cf_first_message,
        );

        let party2_vk = compute_vk(&public_key, &coin_flip_res.party2_alpha);

        assert_eq!(party1_vk, party2_vk);

        // round 3
        // party1:
        let (party1_eph_first_message, party1_comm_witness, party1_eph_keys) =
            Party1EphKeyGenFirstMsg::create_commitments(&party1_vk, &message);
        // party2:
        let (party2_eph_first_message, party2_eph_keys) =
            Party2EphKeyGenFirstMsg::create(&party2_vk, &message);
        // round 4
        // party1
        let party1_eph_second_message = Party1EphKeyGenSecondMsg::verify_and_decommit(
            party1_comm_witness,
            &party2_eph_first_message,
        )
        .expect("failed to verify and decommit");
        // compute R:
        let party1_R = compute_R(&party1_eph_keys, &party2_eph_first_message.public_share);
        // party2
        let _party_two_second_message =
            Party2EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party1_eph_first_message,
                &party1_eph_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
        let party2_R = compute_R(
            &party2_eph_keys,
            &party1_eph_second_message.comm_witness.public_share,
        );

        assert_eq!(party1_R, party2_R);

        // round 5
        // party1
        let party1_local_sig = Party1LocalSignatureMsg::compute_s1(
            &party1_R,
            &party1_vk,
            party1_keys,
            party1_eph_keys,
            &message,
            &party1_alpha,
        );
        // party2
        let party2_local_sig = Party2LocalSignatureMsg::compute_s2(
            &party2_R,
            &party2_vk,
            party2_keys,
            party2_eph_keys,
            &message,
        );

        // party1
        let party1_sig = Party1LocalSignatureMsg::compute(
            party1_R,
            party1_vk,
            &party1_local_sig,
            &party2_local_sig,
            &message,
        );
        // party2
        let party2_sig = Party2LocalSignatureMsg::compute(
            party2_R,
            party2_vk,
            &party2_local_sig,
            &party1_local_sig,
            &message,
        );

        assert_eq!(party1_sig, party2_sig);
    }

    pub fn two_party_keygen() -> (EcKeyPair, EcKeyPair, GE) {
        // round 1
        // party1:
        let (party1_first_message, comm_witness, party1_keys) =
            Party1KeyGenFirstMsg::create_commitments();
        // party2:
        let (party2_first_message, party2_keys) = Party2KeyGenFirstMsg::create();
        // round 2
        // party1
        let party1_second_message = Party1KeyGenSecondMsg::verify_and_decommit(
            comm_witness,
            &party2_first_message.d_log_proof,
        )
        .expect("failed to verify and decommit");
        // compute ak:
        let party1_ak = compute_ak(&party1_keys, &party2_first_message.public_share);
        // party2
        let _party_two_second_message = Party2KeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &party1_first_message,
            &party1_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
        let _party2_ak = compute_ak(
            &party2_keys,
            &party1_second_message.comm_witness.public_share,
        );

        (party1_keys, party2_keys, party1_ak)
    }
}
