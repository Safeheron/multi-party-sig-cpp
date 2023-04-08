
#include "context.h"

#include <utility>
#include "crypto-bn/rand.h"
#include "crypto-curve/curve.h"
#include "../sign_key.h"

using safeheron::bignum::BN;
using safeheron::mpc_flow::mpc_parallel_v2::MPCContext;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {

Context::Context(int total_parties): MPCContext(total_parties){
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    curve_type_ = ctx.curve_type_;
    sign_key_ = ctx.sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;

    rho_ = ctx.rho_;
    X_ = ctx.X_;
    // End Assignments.

    BindAllRounds();
}

Context &Context::operator=(const Context &ctx){
    if (this == &ctx) {
        return *this;
    }

    MPCContext::operator=(ctx);

    // Assign all the member variables.
    curve_type_ = ctx.curve_type_;
    sign_key_ = ctx.sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;

    rho_ = ctx.rho_;
    X_ = ctx.X_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx,
                   const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &minimal_sign_key,
                   const std::string &sid) {

    SignKey &sign_key = ctx.sign_key_;
    if(minimal_sign_key.X_.GetCurveType() == curve::CurveType::INVALID_CURVE) return false;
    const curve::Curve *curv = curve::GetCurveParam(minimal_sign_key.X_.GetCurveType());
    if(!curv) return false;
    ctx.curve_type_ = minimal_sign_key.X_.GetCurveType();

    // Global parameters
    sign_key.n_parties_ = minimal_sign_key.n_parties_;
    sign_key.threshold_ = minimal_sign_key.threshold_;

    // Local party
    sign_key.local_party_.party_id_ = minimal_sign_key.local_party_.party_id_;
    sign_key.local_party_.index_ = minimal_sign_key.local_party_.index_;
    sign_key.local_party_.x_ = minimal_sign_key.local_party_.x_;
    sign_key.local_party_.X_ = curv->g * minimal_sign_key.local_party_.x_;

    // Remote party
    for (size_t i = 0; i < minimal_sign_key.remote_parties_.size(); ++i) {
        sign_key.remote_parties_.emplace_back();
        sign_key.remote_parties_[i].party_id_ = minimal_sign_key.remote_parties_[i].party_id_;
        sign_key.remote_parties_[i].index_ = minimal_sign_key.remote_parties_[i].index_;
        sign_key.remote_parties_[i].X_= minimal_sign_key.remote_parties_[i].X_;
    }
    for (size_t i = 0; i < minimal_sign_key.remote_parties_.size(); ++i) {
        ctx.remote_parties_.emplace_back(RemoteTParty());
    }

    sign_key.X_ = minimal_sign_key.X_;
    return true;
}

void Context::BindAllRounds() {
    RemoveAllRounds();
    AddRound(&round0_);
    AddRound(&round1_);
    AddRound(&round2_);
    AddRound(&round3_);
}

}
}
}
}
