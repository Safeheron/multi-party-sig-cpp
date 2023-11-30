#include "crypto-suites/crypto-sss/polynomial.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/context.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
Context::Context(): MPCContext(2), curve_type_(safeheron::curve::CurveType::INVALID_CURVE) {
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    curve_type_ = ctx.curve_type_;
    x_i_ = ctx.x_i_;
    x_ki_ = ctx.x_ki_;
    X_k_ = ctx.X_k_;
    local_party_ = ctx.local_party_;
    remote_party_ = ctx.remote_party_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
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
    x_i_ = ctx.x_i_;
    x_ki_ = ctx.x_ki_;
    X_k_ = ctx.X_k_;
    local_party_ = ctx.local_party_;
    remote_party_ = ctx.remote_party_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx,
                   safeheron::curve::CurveType curve_type,
                   const safeheron::bignum::BN &x,
                   const safeheron::bignum::BN &i,
                   const safeheron::bignum::BN &j,
                   const safeheron::bignum::BN &k,
                   const std::string &local_party_id,
                   const std::string &remote_party_id) {
    ctx.local_party_.party_id_ = local_party_id;

    if(curve_type == curve::CurveType::INVALID_CURVE) return false;
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam( curve_type);
    if (!curv) return false;
    ctx.curve_type_ = curve_type;

    if (x >= curv->n || x <= safeheron::bignum::BN::ZERO) return false;
    ctx.x_i_ = x;
    ctx.local_party_.X_i_ = curv->g * ctx.x_i_;

    ctx.local_party_.i_ = i % curv->n;
    ctx.local_party_.j_ = j % curv->n;
    ctx.local_party_.k_ = k % curv->n;

    std::vector<safeheron::bignum::BN> index_arr;
    index_arr.push_back(ctx.local_party_.i_);
    index_arr.push_back(ctx.local_party_.j_);
    index_arr.push_back(ctx.local_party_.k_);
    bool ok = CheckIndexArr(index_arr, curv->n);
    if (!ok) return false;

    // Compute lambda of all parties
    safeheron::sss::Polynomial::GetLArray(ctx.local_party_.l_arr_i_j_k_, safeheron::bignum::BN::ZERO, index_arr, curv->n);

    index_arr.clear();
    index_arr.push_back(ctx.local_party_.i_);
    index_arr.push_back(ctx.local_party_.j_);
    safeheron::sss::Polynomial::GetLArray(ctx.local_party_.l_arr_i_j_, safeheron::bignum::BN::ZERO, index_arr, curv->n);

    index_arr.clear();
    index_arr.push_back(ctx.local_party_.i_);
    index_arr.push_back(ctx.local_party_.k_);
    safeheron::sss::Polynomial::GetLArray(ctx.local_party_.l_arr_i_k_, safeheron::bignum::BN::ZERO, index_arr, curv->n);

    ctx.remote_party_.party_id_ = remote_party_id;

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

