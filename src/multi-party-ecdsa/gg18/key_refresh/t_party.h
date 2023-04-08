

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_T_PARTY_H


#include "proto_gen/key_refresh.pb.switch.h"
#include "crypto-sss/vsss.h"
#include "crypto-bn/bn.h"
#include "crypto-paillier/pail.h"
#include "crypto-curve/curve.h"
#include "crypto-zkp/zkp.h"
#include "mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "crypto-commitment/kgd_number.h"

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
    zkp::pail::PailProof pail_proof_;
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
    int ack_status_;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_T_PARTY_H
