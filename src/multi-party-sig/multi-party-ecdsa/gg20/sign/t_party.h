#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG20_SIGN_ONCE_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG20_SIGN_ONCE_T_PARTY_H

#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{


class LocalTParty {
public:
    // for phase 1
    safeheron::bignum::BN lambda_;
    std::vector<safeheron::bignum::BN> l_arr_;
    safeheron::bignum::BN gamma_;
    safeheron::bignum::BN k_;
    safeheron::bignum::BN w_;
    safeheron::curve::CurvePoint Gamma_;
    safeheron::bignum::BN com_Gamma_; // Commitment for Gamma = g^gamma
    safeheron::bignum::BN com_Gamma_blinding_factor_; // blinding factor
    // - Mta(k, gamma)/ Mta(k, w) - step 1, construct message a. note that message_a in MTA(k, gamma) is the same as in MTA(k, w)
    safeheron::bignum::BN message_a_;
    safeheron::bignum::BN r_for_pail_for_mta_msg_a_;

    // for phase 2
    safeheron::bignum::BN sigma_;

    // for phase 3
    safeheron::bignum::BN delta_;
    safeheron::curve::CurvePoint H_;
    safeheron::curve::CurvePoint T_;
    safeheron::zkp::pedersen_proof::PedersenProof pedersen_proof_;

    // for phase 4

    // for phase 5
    safeheron::curve::CurvePoint Ri_; // Ri = R^ki
    safeheron::zkp::pail::PailEncGroupEleRangeProof pail_enc_group_ele_range_proof_;

    // for phase 6
    safeheron::curve::CurvePoint S_; // Si = R^sigma
    safeheron::bignum::BN l_;
    safeheron::zkp::heg::HEGProof_V3 heg_proof_;

    // for phase 7
    safeheron::bignum::BN sig_share_;

    LocalTParty() {}
};

class RemoteTParty {
public:
    // phase 1
    safeheron::bignum::BN lambda_;
    safeheron::bignum::BN com_Gamma_; // Commitment for Gamma = g^gamma
    safeheron::zkp::pail::PailEncRangeProof_V1 alice_proof_; // ZK proof

    // phase 2
    // Receive message A of MTA
    safeheron::bignum::BN receive_message_a_;
    // - Mta(k, gamma) - step 2, construct message b
    safeheron::bignum::BN message_b_for_k_gamma_;
    safeheron::bignum::BN beta_tag_for_mta_k_gamma_msg_b_;
    safeheron::bignum::BN r_for_pail_for_mta_k_gamma_msg_b_;
    // - Mta(k, w) - step 2, construct message b
    safeheron::bignum::BN message_b_for_k_w_;
    safeheron::bignum::BN beta_tag_for_mta_k_w_msg_b_;
    safeheron::bignum::BN r_for_pail_for_mta_k_w_msg_b_;
    // - Mta(k, gamma) - step 3
    safeheron::bignum::BN beta_for_k_gamma_;
    safeheron::bignum::BN alpha_for_k_gamma_;
    // - Mta(k, w) - step 3
    safeheron::bignum::BN beta_for_k_w_;
    safeheron::bignum::BN alpha_for_k_w_;
    // - bob proof for MTA(k, gamma) and MTA(k, w)
    safeheron::zkp::pail::PailAffRangeProof bob_proof_1_;
    safeheron::zkp::pail::PailAffGroupEleRangeProof_V1 bob_proof_2_;

    // for phase 3
    safeheron::bignum::BN delta_;
    safeheron::curve::CurvePoint H_;
    safeheron::curve::CurvePoint T_;

    // for phase 4
    safeheron::bignum::BN com_Gamma_blinding_factor_; // blinding factor
    safeheron::curve::CurvePoint Gamma_;

    // for phase 5
    safeheron::curve::CurvePoint Ri_; // Ri = R^ki
    safeheron::zkp::pail::PailEncGroupEleRangeProof pail_enc_group_ele_range_proof_;

    // for phase 6
    safeheron::curve::CurvePoint S_; // Si = R^sigma

    RemoteTParty() {}
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG20_SIGN_ONCE_T_PARTY_H
