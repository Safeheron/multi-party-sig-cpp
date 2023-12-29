#include <utility>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/mpc-flow/common/sid_maker.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/context.h"

using safeheron::bignum::BN;
using safeheron::mpc_flow::mpc_parallel_v2::MPCContext;
using safeheron::mpc_flow::common::SIDMaker;

static bool Ntilde_range_check(const safeheron::bignum::BN &N,
                                 const safeheron::bignum::BN &s,
                                 const safeheron::bignum::BN &t,
                                 const safeheron::bignum::BN &p,
                                 const safeheron::bignum::BN &q,
                                 const safeheron::bignum::BN &alpha,
                                 const safeheron::bignum::BN &beta) {
    const uint32_t PRIME_BITS = 1024;
    if (N <= 1 || N.BitLength() < 2046) {
        return false;
    }
    if (s <= 1 || s >= N) {
        return false;
    }
    if (t <= 1 || t >= N) {
        return false;
    }

    if (!p.IsProbablyPrime() || !q.IsProbablyPrime()) {
        return false;
    }
    safeheron::bignum::BN P = p * 2 + 1;
    safeheron::bignum::BN Q = q * 2 + 1;
    if (P.BitLength() < PRIME_BITS || Q.BitLength() < PRIME_BITS) {
        return false;
    }
    if (!P.IsProbablyPrime() || !Q.IsProbablyPrime()) {
        return false;
    }
    if (P * Q != N) {
        return false;
    }

    if (alpha <= 1 || alpha >= N) {
        return false;
    }
    if (beta <= 1 || beta >= N) {
        return false;
    }
    if (alpha.InvM(p * q) != beta) {
        return false;
    }
    if (s.PowM(alpha, N) != t) {
        return false;
    }
    return true;
}

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {

Context::Context(int total_parties): MPCContext(total_parties), flag_prepare_pail_key_(false) , flag_update_minimal_key_(true) {
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    ssid_ = ctx.ssid_;
    curve_type_ = ctx.curve_type_;
    sign_key_ = ctx.sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;

    flag_update_minimal_key_ = ctx.flag_update_minimal_key_;

    flag_prepare_pail_key_ = ctx.flag_prepare_pail_key_;

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
    ssid_ = ctx.ssid_;
    curve_type_ = ctx.curve_type_;
    sign_key_ = ctx.sign_key_;
    local_party_ = ctx.local_party_;
    remote_parties_ = ctx.remote_parties_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;

    flag_update_minimal_key_ = ctx.flag_update_minimal_key_;

    flag_prepare_pail_key_ = ctx.flag_prepare_pail_key_;

    rho_ = ctx.rho_;
    X_ = ctx.X_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx,
                   const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &minimal_sign_key,
                   const std::string &sid,
                   bool flag_update_minimal_key) {

    SignKey &sign_key = ctx.sign_key_;
    if(minimal_sign_key.X_.GetCurveType() == curve::CurveType::INVALID_CURVE) return false;
    const curve::Curve *curv = curve::GetCurveParam(minimal_sign_key.X_.GetCurveType());
    if(!curv) return false;
    ctx.curve_type_ = minimal_sign_key.X_.GetCurveType();

    ctx.flag_update_minimal_key_ = flag_update_minimal_key;

    // Global parameters
    sign_key.n_parties_ = minimal_sign_key.n_parties_;
    sign_key.threshold_ = minimal_sign_key.threshold_;
    sign_key.rid_ = minimal_sign_key.rid_;

    // Local party
    sign_key.local_party_.party_id_ = minimal_sign_key.local_party_.party_id_;
    sign_key.local_party_.index_ = minimal_sign_key.local_party_.index_;
    sign_key.local_party_.x_ = minimal_sign_key.local_party_.x_;
    sign_key.local_party_.X_ = curv->g * minimal_sign_key.local_party_.x_;

    // Remote party
    for (size_t j = 0; j < minimal_sign_key.remote_parties_.size(); ++j) {
        sign_key.remote_parties_.emplace_back();
        sign_key.remote_parties_[j].party_id_ = minimal_sign_key.remote_parties_[j].party_id_;
        sign_key.remote_parties_[j].index_ = minimal_sign_key.remote_parties_[j].index_;
        sign_key.remote_parties_[j].X_= minimal_sign_key.remote_parties_[j].X_;
    }
    for (size_t j = 0; j < minimal_sign_key.remote_parties_.size(); ++j) {
        ctx.remote_parties_.emplace_back(RemoteTParty());
    }

    sign_key.X_ = minimal_sign_key.X_;

    ctx.ComputeSSID(sid);
    ctx.ComputeSSID_Index();

    return true;
}

bool Context::CreateContext(Context &ctx,
                            const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &minimal_sign_key,
                            const std::string &sid,
                            const safeheron::bignum::BN &N,
                            const safeheron::bignum::BN &s,
                            const safeheron::bignum::BN &t,
                            const safeheron::bignum::BN &p,
                            const safeheron::bignum::BN &q,
                            const safeheron::bignum::BN &alpha,
                            const safeheron::bignum::BN &beta,
                            bool flag_update_minimal_key) {
    SignKey &sign_key = ctx.sign_key_;
    if(minimal_sign_key.X_.GetCurveType() == curve::CurveType::INVALID_CURVE) return false;
    const curve::Curve *curv = curve::GetCurveParam(minimal_sign_key.X_.GetCurveType());
    if(!curv) return false;
    ctx.curve_type_ = minimal_sign_key.X_.GetCurveType();

    ctx.flag_update_minimal_key_ = flag_update_minimal_key;

    // Global parameters
    sign_key.n_parties_ = minimal_sign_key.n_parties_;
    sign_key.threshold_ = minimal_sign_key.threshold_;
    sign_key.rid_ = minimal_sign_key.rid_;

    // Local party
    sign_key.local_party_.party_id_ = minimal_sign_key.local_party_.party_id_;
    sign_key.local_party_.index_ = minimal_sign_key.local_party_.index_;
    sign_key.local_party_.x_ = minimal_sign_key.local_party_.x_;
    sign_key.local_party_.X_ = curv->g * minimal_sign_key.local_party_.x_;

    // Remote party
    for (size_t j = 0; j < minimal_sign_key.remote_parties_.size(); ++j) {
        sign_key.remote_parties_.emplace_back();
        sign_key.remote_parties_[j].party_id_ = minimal_sign_key.remote_parties_[j].party_id_;
        sign_key.remote_parties_[j].index_ = minimal_sign_key.remote_parties_[j].index_;
        sign_key.remote_parties_[j].X_= minimal_sign_key.remote_parties_[j].X_;
    }
    for (size_t j = 0; j < minimal_sign_key.remote_parties_.size(); ++j) {
        ctx.remote_parties_.emplace_back(RemoteTParty());
    }

    sign_key.X_ = minimal_sign_key.X_;

    if (!Ntilde_range_check(N, s, t, p, q, alpha, beta)) return false;

    sign_key.local_party_.N_ = N;
    sign_key.local_party_.s_ = s;
    sign_key.local_party_.t_ = t;
    sign_key.local_party_.alpha_ = alpha;
    sign_key.local_party_.beta_ = beta;

    ctx.local_party_.pp_ = p;
    ctx.local_party_.qq_ = q;

    sign_key.local_party_.p_ = ctx.local_party_.pp_ * 2 + 1;
    sign_key.local_party_.q_ = ctx.local_party_.qq_ * 2 + 1;

    ctx.flag_prepare_pail_key_ = true;

    ctx.ComputeSSID(sid);
    ctx.ComputeSSID_Index();

    return true;
}

void Context::ComputeSSID(const std::string &sid){
    // Compute ssid = (sid, g, q, P, rid, X)
    const curve::Curve *curv = curve::GetCurveParam(curve_type_);
    SIDMaker sid_maker;
    sid_maker.Append(sid);
    sid_maker.Append(sign_key_.rid_);
    sid_maker.Append(curv->g);
    sid_maker.Append(curv->n);

    auto GetX = [&](const BN &index) {
        for(const auto &party: sign_key_.remote_parties_){
            if(party.index_ == index) return party.X_;
        }
        return sign_key_.local_party_.X_;
    };

    // Construct an ordered party index array
    std::vector<safeheron::bignum::BN> t_party_index_arr;
    t_party_index_arr.push_back(sign_key_.local_party_.index_);
    for(const auto &party: sign_key_.remote_parties_){
        t_party_index_arr.push_back(party.index_);
    }
    std::sort(t_party_index_arr.begin(), t_party_index_arr.end());
    // Append all parties [ (i, X_i) ]
    for (const auto & pi : t_party_index_arr) {
        sid_maker.Append(pi);
        sid_maker.Append(GetX(pi));
    }
    sid_maker.Finalize(ssid_);
}

void Context::ComputeSSID_Index(){
    std::string t_ssid;
    SIDMaker ssid_maker;

    // Set local sid_index = (sid, index)
    ssid_maker.Append(ssid_);
    ssid_maker.Append(sign_key_.local_party_.index_);
    ssid_maker.Finalize(local_party_.sid_index_);

    for(size_t j = 0; j < remote_parties_.size(); ++j){
        // Set remote ssid_pid = (sid, pid, rid)
        ssid_maker.Reset();
        ssid_maker.Append(ssid_);
        ssid_maker.Append(sign_key_.remote_parties_[j].index_);
        ssid_maker.Finalize(remote_parties_[j].ssid_index_);
    }
}

void Context::ComputeSSID_Rho_Index(){
    std::string t_ssid;
    SIDMaker ssid_maker;

    // Set local ssid_rho_index = (ssid, rho, index)
    ssid_maker.Append(ssid_);
    ssid_maker.Append(rho_);
    ssid_maker.Append(sign_key_.local_party_.index_);
    ssid_maker.Finalize(local_party_.sid_rho_index_);

    for(size_t j = 0; j < remote_parties_.size(); ++j){
        // Set remote ssid_rho_index = (ssid, rho, index)
        ssid_maker.Reset();
        ssid_maker.Append(ssid_);
        ssid_maker.Append(rho_);
        ssid_maker.Append(sign_key_.remote_parties_[j].index_);
        ssid_maker.Finalize(remote_parties_[j].ssid_rho_index_);
    }
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
