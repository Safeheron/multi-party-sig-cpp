#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_T_PARTY_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-zkp/dlog_proof_v2.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {

class LocalTParty {
public:
    std::string party_id_;

    safeheron::curve::CurvePoint X_i_;
    safeheron::bignum::BN r_i_;
    safeheron::curve::CurvePoint R_i_;
    safeheron::zkp::dlog::DLogProof_V2 phi_i_;

    std::vector<safeheron::bignum::BN> l_arr_i_j_k_;
    std::vector<safeheron::bignum::BN> l_arr_i_j_;
    std::vector<safeheron::bignum::BN> l_arr_i_k_;

    //three party indexes
    safeheron::bignum::BN i_;
    safeheron::bignum::BN j_;
    safeheron::bignum::BN k_;

    safeheron::bignum::BN a_i_;
    safeheron::curve::CurvePoint A_i_;

    safeheron::curve::CurvePoint X_ki_;
    safeheron::bignum::BN t_i_;
    safeheron::curve::CurvePoint T_i_;
    safeheron::zkp::dlog::DLogProof_V2 psi_i_;

    safeheron::curve::CurvePoint X_prime_;  // X'
    safeheron::curve::CurvePoint X_double_prime_; // X''

    std::string V_i_;
};

class RemoteTParty {
public:
    std::string party_id_;

    safeheron::curve::CurvePoint A_j_;

    safeheron::curve::CurvePoint X_j_;
    safeheron::curve::CurvePoint R_j_;

    safeheron::curve::CurvePoint X_kj_;
    safeheron::curve::CurvePoint T_j_;

    std::string V_j_;
};

}
}
}
}
#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_T_PARTY_H
