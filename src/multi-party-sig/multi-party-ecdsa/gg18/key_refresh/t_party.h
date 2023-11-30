

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_T_PARTY_H


#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/proto_gen/key_refresh.pb.switch.h"


namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {



class LocalTParty {
public:
    safeheron::bignum::BN x_ij_;
    safeheron::bignum::BN new_x_;
    safeheron::curve::CurvePoint new_X_;
    std::string blind_factor_;
    std::string V_;

    // Paillier proof
    zkp::pail::PailBlumModulusProof pail_proof_;
    // DLN Proof
    zkp::dln_proof::DLNProof dln_proof_1_;
    zkp::dln_proof::DLNProof dln_proof_2_;
    // Dlog Proof
    safeheron::zkp::dlog::DLogProof dlog_proof_x_;
    std::vector<safeheron::bignum::BN> l_arr_;

    // Random numbers for commitment, polynomial coefficients
    safeheron::bignum::BN rand_num_for_schnorr_proof_;
    std::vector<safeheron::bignum::BN> rand_num_arr_for_polynomial_coe_;

    // Chain code share
    std::vector<safeheron::sss::Point> share_points_;
    std::vector<safeheron::curve::CurvePoint> vs_;
    int ack_status_;
};

class RemoteTParty {
public:
    std::string V_;
    safeheron::bignum::BN x_ij_;
    // No small factor proof
    safeheron::zkp::no_small_factor_proof::NoSmallFactorProof nsf_proof_;
    int ack_status_;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_T_PARTY_H
