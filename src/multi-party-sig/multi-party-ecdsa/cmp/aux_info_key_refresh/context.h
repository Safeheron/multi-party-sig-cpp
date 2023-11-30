#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_CONTEXT_H

#include <vector>
#include "crypto-suites/crypto-bn/bn.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/party.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/t_party.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round1.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round3.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {

class Context : public safeheron::mpc_flow::mpc_parallel_v2::MPCContext {
public:
    /**
     * Default constructor
     */
    Context(int total_parties);

    /**
     * A copy constructor
     */
    Context(const Context &ctx);

    /**
     * A copy assignment operator
     */
    Context &operator=(const Context &ctx);

public:
    void BindAllRounds();

    static bool CreateContext(Context &ctx,
                              const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &minimal_sign_key,
                              const std::string &sid,
                              bool flag_update_minimal_key = true);

    static bool CreateContext(Context &ctx,
                              const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &minimal_sign_key,
                              const std::string &sid,
                              const safeheron::bignum::BN &N,
                              const safeheron::bignum::BN &s,
                              const safeheron::bignum::BN &t,
                              const safeheron::bignum::BN &p,
                              const safeheron::bignum::BN &q,
                              const safeheron::bignum::BN &alpha,
                              const safeheron::bignum::BN &beta,
                              bool flag_update_minimal_key = true);

    const safeheron::curve::Curve * GetCurrentCurve() const{
        assert(curve_type_ != safeheron::curve::CurveType::INVALID_CURVE);
        const safeheron::curve::Curve* curv = safeheron::curve::GetCurveParam(curve_type_);;
        assert(curv);
        return curv;
    }

    safeheron::curve::CurveType GetCurrentCurveType() const{
        assert(curve_type_ != safeheron::curve::CurveType::INVALID_CURVE);
        return curve_type_;
    }

    void ComputeSSID(const std::string &sid);

    void ComputeSSID_Index();

    void ComputeSSID_Rho_Index();

public:
    safeheron::curve::CurveType curve_type_;
    SignKey sign_key_;
    LocalTParty local_party_;
    std::vector<RemoteTParty> remote_parties_;
    Round0 round0_;
    Round1 round1_;
    Round2 round2_;
    Round3 round3_;

    bool flag_prepare_pail_key_;

    std::string ssid_;
    std::string rho_;
    safeheron::curve::CurvePoint X_;

    bool flag_update_minimal_key_; //update the private key shards or not
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_CONTEXT_H
