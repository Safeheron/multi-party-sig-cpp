
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/context.h"

#include <utility>
#include "crypto-suites/crypto-bn/rand.h"
#include "../../gg18/util.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::gg18::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{

Context::Context(int total_parties): MPCContext(total_parties){
    // Assign all the member variables.
    // End Assignments.
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    sign_key_ = ctx.sign_key_;

    m_ = ctx.m_;

    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;
    round5_ = ctx.round5_;
    round6_ = ctx.round6_;
    round7_ = ctx.round7_;

    delta_ = ctx.delta_;
    R_ = ctx.R_;
    r_ = ctx.r_;
    s_ = ctx.s_;
    v_ = ctx.v_;
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

    m_ = ctx.m_;

    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;
    round5_ = ctx.round5_;
    round6_ = ctx.round6_;
    round7_ = ctx.round7_;

    delta_ = ctx.delta_;
    R_ = ctx.R_;
    r_ = ctx.r_;
    s_ = ctx.s_;
    v_ = ctx.v_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx, const std::string &sign_key_base64, const safeheron::bignum::BN &m) {
    bool ok = true;
    ctx.m_ = m;

    ok = ctx.sign_key_.FromBase64(sign_key_base64);
    if (!ok) return false;
    ok = ((int)ctx.sign_key_.n_parties_ == ctx.get_total_parties());
    if (!ok) return false;

    for (uint32_t i = 0; i < ctx.sign_key_.n_parties_ - 1; ++i) {
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
    AddRound(&round5_);
    AddRound(&round6_);
    AddRound(&round7_);
}

}
}
}
}
