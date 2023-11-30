

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_T_PARTY_H


#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-commitment/commitment.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/proto_gen/key_gen.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_gen {


class LocalTParty {
public:
    // Original secret share
    safeheron::bignum::BN u_;
    // y = g^u
    safeheron::curve::CurvePoint y_;

    // Commitment of secret share
    std::vector<safeheron::sss::Point> share_points_;
    std::vector<safeheron::curve::CurvePoint> vs_;

    // Random numbers for polynomial coefficients
    safeheron::bignum::BN rand_num_for_schnorr_proof_;
    std::vector<safeheron::bignum::BN> rand_polynomial_coe_arr_;

    // dlog proof
    zkp::dlog::DLogProof dlog_proof_x_;

    // [KGC, KGD] = Com(y_i)
    safeheron::bignum::BN kgc_y_;
    commitment::KgdCurvePoint kgd_y_;

    // Paillier proof
    zkp::pail::PailBlumModulusProof pail_proof_;

    // DLN Proof
    zkp::dln_proof::DLNProof dln_proof1_;
    zkp::dln_proof::DLNProof dln_proof2_;
};

class RemoteTParty {
public:
    // y = g^u
    safeheron::curve::CurvePoint y_;

    // [KGC, KGD] = Com(y_i)
    safeheron::bignum::BN kgc_y_;

    // No small factor proof
    safeheron::zkp::no_small_factor_proof::NoSmallFactorProof nsf_proof_;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_T_PARTY_H
