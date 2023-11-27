#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_T_PARTY_H
#include "crypto-bn/bn.h"
#include "crypto-curve/curve_point.h"
#include "crypto-zkp/dlog_proof_v2.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {

class LocalTParty {
public:
    std::string party_id_;

    safeheron::curve::CurvePoint X_;
    safeheron::bignum::BN r_;
    safeheron::curve::CurvePoint R_;
    safeheron::zkp::dlog::DLogProof_V2 phi_;

    std::vector<safeheron::bignum::BN> l_arr_;
    std::vector<safeheron::bignum::BN> l_arr_i_j_;
    std::vector<safeheron::bignum::BN> l_arr_i_k_;

    //three party indexes
    safeheron::bignum::BN i_;
    safeheron::bignum::BN j_;
    safeheron::bignum::BN k_;

    safeheron::bignum::BN a_;
    safeheron::bignum::BN b_;
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint B_;

    safeheron::curve::CurvePoint S_;
    safeheron::bignum::BN t_;
    safeheron::curve::CurvePoint T_;
    safeheron::zkp::dlog::DLogProof_V2 psi_;

    std::string V_;
};

class RemoteTParty {
public:
    std::string party_id_;

    safeheron::bignum::BN i_;
    safeheron::bignum::BN j_;
    safeheron::bignum::BN k_;

    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint B_;

    safeheron::curve::CurvePoint X_;
    safeheron::curve::CurvePoint R_;

    safeheron::curve::CurvePoint S_;
    safeheron::curve::CurvePoint T_;

    std::string V_;
};

}
}
}
}
#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_T_PARTY_H
