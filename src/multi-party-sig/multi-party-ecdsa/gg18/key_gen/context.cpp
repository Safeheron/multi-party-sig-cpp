#include <utility>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/context.h"

using safeheron::bignum::BN;
using safeheron::mpc_flow::mpc_parallel_v2::MPCContext;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_gen {

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

    X_ = ctx.X_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            const std::string &workspace_id,
                            uint32_t threshold,
                            uint32_t n_parties,
                            const std::string &party_id,
                            const safeheron::bignum::BN &index,
                            const std::vector<std::string> &remote_party_id_arr) {
    ctx.curve_type_ = curve_type;

    // Alias name of SignKey
    SignKey &sign_key = ctx.sign_key_;

    bool ok = (n_parties == remote_party_id_arr.size() + 1) && threshold <= n_parties;
    if (!ok) return false;

    assert(threshold > 1);

    // Global parameters
    sign_key.workspace_id_ = workspace_id;
    sign_key.threshold_ = threshold;
    sign_key.n_parties_ = n_parties;

    // Local party
    sign_key.local_party_.party_id_ = party_id;
    sign_key.local_party_.index_ = index;

    // Remote parties
    for (size_t i = 0; i < n_parties - 1; ++i) {
        sign_key.remote_parties_.emplace_back();
        sign_key.remote_parties_[i].party_id_ = remote_party_id_arr[i];
    }

    for (size_t i = 0; i < n_parties - 1; ++i) {
        ctx.remote_parties_.emplace_back();
    }

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
