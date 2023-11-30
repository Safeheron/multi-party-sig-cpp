

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_ONCE_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_ONCE_T_PARTY_H


#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-commitment/commitment.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace sign{

class LocalTParty {
public:
    // Phase 1 ( Round 0)
    safeheron::bignum::BN lambda_;
    std::vector<safeheron::bignum::BN> l_arr_;
    // - Sample gamma, k
    safeheron::bignum::BN gamma_;
    safeheron::bignum::BN k_;
    safeheron::bignum::BN w_;
    // - Commitment for g_mamma
    safeheron::curve::CurvePoint Gamma_;
    safeheron::bignum::BN commitment_Gamma_;
    safeheron::bignum::BN blind_factor_1_;

    // - Mta(k, gamma)/ Mta(k, w) - step 1, construct message a. note that message_a in MTA(k, gamma) is the same as in MTA(k, w)
    safeheron::bignum::BN message_a_;
    safeheron::bignum::BN r_for_pail_for_mta_msg_a_;

    // Phase 3
    safeheron::bignum::BN delta_;
    safeheron::bignum::BN sigma_;

    // Phase 4
    safeheron::bignum::BN rand_num_for_proof_gamma_;
    safeheron::zkp::dlog::DLogProof dlog_proof_gamma_;

    // Phase 5
    safeheron::bignum::BN si_;
    safeheron::bignum::BN l_;
    safeheron::bignum::BN rho_;
    safeheron::curve::CurvePoint V_;
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint U_;
    safeheron::curve::CurvePoint T_;
    safeheron::zkp::linear_combination::LinearCombinationWitness lc_witness_VRG_;
    safeheron::zkp::linear_combination::LinearCombinationStatement lc_statement_VRG_;
    safeheron::zkp::linear_combination::LinearCombinationProof lc_proof_VRG_;
    safeheron::bignum::BN commitment_VA_;
    safeheron::bignum::BN commitment_UT_;
    safeheron::bignum::BN blind_factor_2_;
    safeheron::bignum::BN blind_factor_3_;
    safeheron::zkp::dlog::DLogProof_V2 dlog_proof_rho_;
};

class RemoteTParty {
public:
    // Phase 1 (Round 0)
    safeheron::bignum::BN lambda_;

    // Phase 2
    // Com(g_gamma)
    safeheron::bignum::BN commitment_Gamma_;
    safeheron::bignum::BN receive_message_a_;
    safeheron::zkp::pail::PailEncRangeProof_V1 alice_proof_; // ZK proof
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

    // Phase 4
    safeheron::curve::CurvePoint Gamma_;

    // Phase 5
    safeheron::curve::CurvePoint V_;
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint U_;
    safeheron::curve::CurvePoint T_;
    safeheron::bignum::BN commitment_VA_;
    safeheron::bignum::BN commitment_UT_;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_ONCE_T_PARTY_H
