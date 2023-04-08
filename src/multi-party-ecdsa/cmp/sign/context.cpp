
#include "context.h"

#include <utility>
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "security_param.h"
#include "crypto-sss/polynomial.h"

using std::vector;
using safeheron::bignum::BN;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

Context::Context(int total_parties): MPCContext(total_parties){
    // Assign all the member variables.
    // End Assignments.
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    ssid_ = ctx.ssid_;
    sign_key_ = ctx.sign_key_;
    m_ = ctx.m_;

    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;

    delta_ = ctx.delta_;
    Gamma_ = ctx.Gamma_;
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
    ssid_ = ctx.ssid_;
    sign_key_ = ctx.sign_key_;
    m_ = ctx.m_;

    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;

    delta_ = ctx.delta_;
    Gamma_ = ctx.Gamma_;
    R_ = ctx.R_;
    r_ = ctx.r_;
    s_ = ctx.s_;
    v_ = ctx.v_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

static void PreprocessSignKey(SignKey &sign_key){
    vector<BN> share_index_arr;
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    const safeheron::curve::Curve * curv = safeheron::curve::GetCurveParam(sign_key.X_.GetCurveType());

    vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);

    sign_key.local_party_.x_ = (sign_key.local_party_.x_ * l_arr.back()) % curv->n;
    sign_key.local_party_.X_ *= l_arr.back();
    for(size_t i = 0; i < sign_key.remote_parties_.size(); ++i){
        sign_key.remote_parties_[i].X_ *= l_arr[i];
    }
}

bool Context::CreateContext(Context &ctx,
                            const std::string &sign_key_base64,
                            const safeheron::bignum::BN &m,
                            const std::string &ssid) {
    bool ok = true;

    SignKey &sign_key = ctx.sign_key_;
    ok = sign_key.FromBase64(sign_key_base64);
    if (!ok) return false;
    ok = ((int)sign_key.n_parties_ == ctx.get_total_parties());
    if (!ok) return false;
    PreprocessSignKey(sign_key);

    ctx.m_ = m;

    // set Paillier key pair of local party
    ctx.local_party_.pail_pub_ = safeheron::pail::PailPubKey(sign_key.local_party_.N_, sign_key.local_party_.N_ + 1);
    const BN &p = sign_key.local_party_.p_;
    const BN &q = sign_key.local_party_.q_;
    const BN N = p * q;
    const BN lambda = (p-1) * (q-1);
    const BN mu = lambda.InvM(N);
    ctx.local_party_.pail_priv_ = safeheron::pail::PailPrivKey(lambda, mu, N);

    // set Paillier public key of remote parties
    for (uint32_t i = 0; i < sign_key.n_parties_ - 1; ++i) {
        ctx.remote_parties_.emplace_back();
        ctx.remote_parties_[i].pail_pub_ = safeheron::pail::PailPubKey(sign_key.remote_parties_[i].N_, sign_key.remote_parties_[i].N_ + 1);
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
