#include <utility>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/mpc-flow/common/sid_maker.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/context.h"

using safeheron::bignum::BN;
using safeheron::mpc_flow::mpc_parallel_v2::MPCContext;
using safeheron::mpc_flow::common::SIDMaker;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {

Context::Context(int total_parties): MPCContext(total_parties){
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    sid_ = ctx.sid_;
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
    // End Assignments.

    BindAllRounds();
}

Context &Context::operator=(const Context &ctx){
    if (this == &ctx) {
        return *this;
    }

    MPCContext::operator=(ctx);

    // Assign all the member variables.
    sid_ = ctx.sid_;
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

    for (size_t i = 0; i < n_parties - 1; ++i) {
        ctx.remote_parties_.emplace_back();
    }

    // Construct an ordered party index array
    std::vector<safeheron::bignum::BN> t_party_index_arr(remote_party_index_arr);
    t_party_index_arr.push_back(index);
    std::sort(t_party_index_arr.begin(), t_party_index_arr.end());
    ctx.ComputeSID(sid);

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
    // Sample x in Zq
    const safeheron::bignum::BN x = safeheron::rand::RandomBNLt(curv->n);
    return CreateContext(ctx, curve_type, threshold, n_parties, x, index, local_party_id, remote_party_index_arr, remote_party_id_arr, sid);
}

void Context::ComputeSID(const std::string &sid){
    // Compute sid = (sid, g, q, P)
    const curve::Curve *curv = curve::GetCurveParam(curve_type_);
    SIDMaker sid_maker;
    sid_maker.Append(sid);
    sid_maker.Append(curv->g);
    sid_maker.Append(curv->n);

    // Construct an ordered party index array
    std::vector<safeheron::bignum::BN> t_party_index_arr;
    t_party_index_arr.push_back(minimal_sign_key_.local_party_.index_);
    for(const auto &party: minimal_sign_key_.remote_parties_){
        t_party_index_arr.push_back(party.index_);
    }
    std::sort(t_party_index_arr.begin(), t_party_index_arr.end());
    // Append all parties [ (i, X_i, Y_i) ]
    for (const auto & pi : t_party_index_arr) {
        sid_maker.Append(pi);
    }
    sid_maker.Finalize(sid_);
}

void Context::ComputeSID_Index_RID(){
    std::string t_ssid;
    SIDMaker ssid_maker;

    // Set local sid_pid_rid = (sid, pid, rid)
    ssid_maker.Append(sid_);
    ssid_maker.Append(minimal_sign_key_.local_party_.index_);
    ssid_maker.Append(rid_);
    ssid_maker.Finalize(local_party_.sid_index_rid_);

    for(size_t j = 0; j < remote_parties_.size(); ++j){
        // Set remote ssid_pid = (sid, pid, rid)
        ssid_maker.Reset();
        ssid_maker.Append(sid_);
        ssid_maker.Append(minimal_sign_key_.remote_parties_[j].index_);
        ssid_maker.Append(rid_);
        ssid_maker.Finalize(remote_parties_[j].sid_index_rid_);
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
