

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_T_PARTY_H


#include "proto_gen/aux_info_key_refresh.pb.switch.h"
#include "crypto-bn/bn.h"
#include "crypto-paillier/pail.h"
#include "crypto-curve/curve.h"
#include "crypto-zkp/zkp.h"
#include "crypto-sss/vsss.h"
#include "mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "crypto-commitment/commitment.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {


class LocalTParty {
public:
    std::string sid_;
    /**
     * N, s, t, p, q, pp, qq, alpha, beta
     * - N = p * q
     * - p = pp * 2 + 1
     * - q = qq * 2 + 1
     * - t = s^alpha mod N
     * - s = t^beta  mod N
     */
    safeheron::bignum::BN pp_;
    safeheron::bignum::BN qq_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;

    //
    safeheron::bignum::BN tau_;
    safeheron::curve::CurvePoint B_; // B = g^tau
    safeheron::bignum::BN y_;

    std::map<std::string, safeheron::bignum::BN> map_remote_party_id_tau_;
    std::map<std::string, safeheron::curve::CurvePoint> map_remote_party_id_A_; // A = g^tau

//    safeheron::bignum::BN x_;
//    safeheron::curve::CurvePoint X_;
    std::map<std::string, safeheron::bignum::BN> map_party_id_x_;
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_X_;
    std::vector<safeheron::curve::CurvePoint> c_; // Commitment of VSS Scheme
    std::vector<safeheron::bignum::BN> f_arr_;

    std::string rho_;
    std::string u_; // blind factor

    std::string V_;
    safeheron::zkp::dln_proof::TwoDLNProof psi_tilde_;
    safeheron::zkp::pail::PailBlumModulusProof psi_;

    safeheron::zkp::dlog::DLogProof_V2 pi_;

    safeheron::bignum::BN C_;
};

class RemoteTParty {
public:
    std::string V_;
    safeheron::bignum::BN x_;
    safeheron::curve::CurvePoint B_; // B = g^tau
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_X_;
    std::vector<safeheron::curve::CurvePoint> c_; // Commitment of VSS Scheme
    std::map<std::string, safeheron::curve::CurvePoint> map_remote_party_id_A_; // A = g^tau
    safeheron::zkp::no_small_factor_proof::NoSmallFactorProof phi_;
    safeheron::zkp::dlog::DLogProof_V2 psi_;
    safeheron::bignum::BN C_;
    std::string rho_;
    std::string u_; // blind factor
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_T_PARTY_H
