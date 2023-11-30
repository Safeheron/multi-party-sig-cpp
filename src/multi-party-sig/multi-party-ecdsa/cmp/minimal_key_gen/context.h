

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_CONTEXT_H

#include <vector>
#include "crypto-suites/crypto-bn/bn.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/party.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/t_party.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round1.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round3.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {

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
                              safeheron::curve::CurveType curve_type,
                              uint32_t threshold, uint32_t n_parties,
                              const safeheron::bignum::BN &x ,
                              const safeheron::bignum::BN &index,
                              const std::string &local_party_id,
                              const std::vector<safeheron::bignum::BN> &remote_party_index_arr,
                              const std::vector<std::string> &remote_party_id_arr,
                              const std::string &sid);

    static bool CreateContext(Context &ctx,
                              safeheron::curve::CurveType curve_type,
                              uint32_t threshold, uint32_t n_parties,
                              const safeheron::bignum::BN &index,
                              const std::string &local_party_id,
                              const std::vector<safeheron::bignum::BN> &remote_party_index_arr,
                              const std::vector<std::string> &remote_party_id_arr,
                              const std::string &sid);

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

    void ComputeSID(const std::string &sid);

    void ComputeSID_Index_RID();

public:
    safeheron::curve::CurveType curve_type_;
    MinimalSignKey minimal_sign_key_;
    LocalTParty local_party_;
    std::vector<RemoteTParty> remote_parties_;
    Round0 round0_;
    Round1 round1_;
    Round2 round2_;
    Round3 round3_;

    std::string rid_;
    std::string sid_;
    safeheron::curve::CurvePoint X_;
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_CONTEXT_H
