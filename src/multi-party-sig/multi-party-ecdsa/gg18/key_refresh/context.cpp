#include <utility>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/util.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/context.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::multi_party_ecdsa::gg18::SignKey;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {

Context::Context(int total_parties): MPCContext(total_parties){
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    sign_key_ = ctx.sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;
    // End Assignments.

    BindAllRounds();
}

Context &Context::operator=(const Context &ctx){
    if (this == &ctx) {
        return *this;
    }

    MPCContext::operator=(ctx);

    // Assign all the member variables.
    sign_key_ = ctx.sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx, std::string &sign_key_base64) {
    bool ok = true;
    ok = ctx.sign_key_.FromBase64(sign_key_base64);
    if (!ok) return false;

    SignKey &sign_key = ctx.sign_key_;

    for (size_t i = 0; i < sign_key.n_parties_ - 1; ++i) {
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
    AddRound(&round4_);
}

}
}
}
}
