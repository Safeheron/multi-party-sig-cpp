

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_T_PARTY_H


#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-sss/vsss.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/proto_gen/minimal_key_gen.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {


class LocalTParty {
public:
    std::string sid_index_rid_;

    std::string rid_;
    safeheron::bignum::BN x_;
    safeheron::curve::CurvePoint X_; // X = g^x
    safeheron::bignum::BN tau_;
    safeheron::curve::CurvePoint A_; // A = g^tau
    safeheron::bignum::BN r_;
    safeheron::curve::CurvePoint B_; // B = g^r
    std::string u_; // blind factor
    std::string V_;
    safeheron::zkp::dlog::DLogProof_V2 psi_;
    safeheron::zkp::dlog::DLogProof_V2 phi_;
    std::map<std::string, safeheron::bignum::BN> map_party_id_x_;
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_X_;
    std::vector<safeheron::curve::CurvePoint> c_; // Commitment of VSS Scheme
    std::vector<safeheron::bignum::BN> f_arr_;
};

class RemoteTParty {
public:
    std::string sid_index_rid_;

    std::string rid_;
    safeheron::bignum::BN x_ij_;
    safeheron::curve::CurvePoint X_; // X = g^x
    safeheron::curve::CurvePoint A_; // A = g^tau
    safeheron::curve::CurvePoint B_; // B = g^r
    std::string u_; // blind factor
    std::string V_;
    safeheron::zkp::dlog::DLogProof_V2 psi_;
    safeheron::zkp::dlog::DLogProof_V2 phi_;
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_X_;
    std::vector<safeheron::curve::CurvePoint> c_; // Commitment of VSS Scheme
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_T_PARTY_H
