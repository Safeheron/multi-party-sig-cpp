
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
namespace minimal_key_gen {

Context::Context(int total_parties): MPCContext(total_parties){
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    curve_type_ = ctx.curve_type_;
    minimal_sign_key_ = ctx.minimal_sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;

    rid_ = ctx.rid_;
    X_ = ctx.X_;
    ssid_ = ctx.ssid_;
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
    minimal_sign_key_ = ctx.minimal_sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;

    rid_ = ctx.rid_;
    X_ = ctx.X_;
    ssid_ = ctx.ssid_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            uint32_t threshold, uint32_t n_parties,
                            const safeheron::bignum::BN &x ,
                            const safeheron::bignum::BN &index,
                            const std::string &local_party_id,
                            const std::vector<safeheron::bignum::BN> &remote_party_index_arr,
                            const std::vector<std::string> &remote_party_id_arr,
                            const std::string &sid) {

    bool ok = true;
    MinimalSignKey &minimal_sign_key = ctx.minimal_sign_key_;
    const curve::Curve *curv = curve::GetCurveParam(curve_type);
    if(curv == nullptr) return false;
    ctx.curve_type_ = curve_type;

    ok = (n_parties == remote_party_id_arr.size() + 1) && threshold <= n_parties;
    if (!ok) return false;

    // Global parameters
    minimal_sign_key.n_parties_ = n_parties;
    minimal_sign_key.threshold_ = threshold;

    // Local party
    minimal_sign_key.local_party_.party_id_ = local_party_id;
    minimal_sign_key.local_party_.index_ = index;
    ctx.local_party_.x_ = x;
    ctx.local_party_.X_ = curv->g * x;

    // Remote party
    for (size_t i = 0; i < n_parties - 1; ++i) {
        minimal_sign_key.remote_parties_.emplace_back();
        minimal_sign_key.remote_parties_[i].party_id_ = remote_party_id_arr[i];
        minimal_sign_key.remote_parties_[i].index_ = remote_party_index_arr[i];
    }

    ctx.ssid_ = sid;

    for (size_t i = 0; i < n_parties - 1; ++i) {
        ctx.remote_parties_.emplace_back();
    }

    return true;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            uint32_t threshold, uint32_t n_parties,
                            const safeheron::bignum::BN &index,
                            const std::string &local_party_id,
                            const std::vector<safeheron::bignum::BN> &remote_party_index_arr,
                            const std::vector<std::string> &remote_party_id_arr,
                            const std::string &sid) {
    const curve::Curve *curv = curve::GetCurveParam(curve_type);
    const safeheron::bignum::BN x = safeheron::rand::RandomBNLt(curv->n);
    return CreateContext(ctx, curve_type, threshold, n_parties, x, index, local_party_id, remote_party_index_arr, remote_party_id_arr, sid);
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
