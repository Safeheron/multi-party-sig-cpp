
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ONCE_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ONCE_CONTEXT_H

#include <vector>
#include "crypto-curve/curve.h"
#include "../util.h"
#include "crypto-bn/bn.h"
#include "mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "../sign_key.h"
#include "t_party.h"
#include "round0.h"
#include "round1.h"
#include "round2.h"
#include "round3.h"
#include "round4.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

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
                              const std::string &sign_key_base64,
                              const safeheron::bignum::BN &m,
                              const std::string &ssid);

    const safeheron::curve::Curve * GetCurrentCurve() const{
        assert(sign_key_.X_.GetCurveType() != safeheron::curve::CurveType::INVALID_CURVE);
        const safeheron::curve::Curve* curv = safeheron::curve::GetCurveParam(sign_key_.X_.GetCurveType());;
        assert(curv);
        return curv;
    }

    safeheron::curve::CurveType GetCurrentCurveType() const{
        assert(sign_key_.X_.GetCurveType() != safeheron::curve::CurveType::INVALID_CURVE);
        return sign_key_.X_.GetCurveType();
    }

public:
    std::string ssid_;
    safeheron::multi_party_ecdsa::cmp::SignKey sign_key_;
    safeheron::bignum::BN m_;

    LocalTParty local_party_;
    std::vector<RemoteTParty> remote_parties_;
    Round0 round0_;
    Round1 round1_;
    Round2 round2_;
    Round3 round3_;
    Round4 round4_;

    // temp data
    safeheron::bignum::BN delta_;
    safeheron::curve::CurvePoint Gamma_;
    safeheron::curve::CurvePoint R_;

    // signature
    safeheron::bignum::BN r_;
    safeheron::bignum::BN s_;
    uint32_t v_;

};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ONCE_CONTEXT_H
