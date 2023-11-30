

#include <utility>
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/exception/safeheron_exceptions.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-sss/polynomial.h"
#include "multi-party-sig/mpc-flow/common/sid_maker.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/security_param.h"

using std::vector;
using safeheron::bignum::BN;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::exception::LocatedException;
using safeheron::mpc_flow::common::SIDMaker;

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

    proof_in_pre_sign_phase_ = ctx.proof_in_pre_sign_phase_;
    proof_in_sign_phase_ = ctx.proof_in_sign_phase_;;

    // culprit
    identify_culprit_ = ctx.identify_culprit_;
    identify_round_index_ = ctx.identify_round_index_;
    identify_need_proof_in_pre_sign_phase_ = ctx.identify_need_proof_in_pre_sign_phase_;
    identify_need_proof_in_sign_phase_ = ctx.identify_need_proof_in_sign_phase_;
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

    proof_in_pre_sign_phase_ = ctx.proof_in_pre_sign_phase_;
    proof_in_sign_phase_ = ctx.proof_in_sign_phase_;;

    // culprit
    identify_culprit_ = ctx.identify_culprit_;
    identify_round_index_ = ctx.identify_round_index_;
    identify_need_proof_in_pre_sign_phase_ = ctx.identify_need_proof_in_pre_sign_phase_;
    identify_need_proof_in_sign_phase_ = ctx.identify_need_proof_in_sign_phase_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

static void PreprocessSignKey(SignKey &sign_key){
    // Compute Lagrange interpolation coefficients {lambda_i} for each party that
    //              lambda_i = \Prod_m { x_m / {x_m - x_j}
    // which could be used to compute private key
    //              x = \sum_i { x_i * lambda_i }  mod q
    vector<BN> share_index_arr;
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    const safeheron::curve::Curve * curv = safeheron::curve::GetCurveParam(sign_key.X_.GetCurveType());

    vector<BN> l_arr;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);
    // Compute:
    // - the additive key shard pair (x_i, X_i) where X_i = g * x_i for local party
    // - and additive public key shards for remote parties.
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

    // Parse the sign key
    SignKey &sign_key = ctx.sign_key_;
    ok = sign_key.FromBase64(sign_key_base64);
    if (!ok) return false;
    ok = ((int)sign_key.n_parties_ == ctx.get_total_parties());
    if (!ok) return false;

    // Preprocessing to generate additive shards
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

    ctx.ComputeSSID(ssid);
    ctx.ComputeSSID_Index();

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

bool Context::IsValidPartyID(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) return true;
    int pos = sign_key_.get_remote_party_pos(party_id);
    return (pos != -1);
}

std::string Context::GetSSIDIndex(const std::string& party_id) const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.ssid_index_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].ssid_index_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}


const safeheron::pail::PailPubKey& Context::GetPailPub(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.pail_pub_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].pail_pub_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetK(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.K_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].K_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetG(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.G_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].G_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetDelta(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.delta_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].delta_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetSigma(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.sigma_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].sigma_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::curve::CurvePoint& Context::GetGamma(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return local_party_.Gamma_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return remote_parties_[pos].Gamma_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::curve::CurvePoint& Context::GetX(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return sign_key_.local_party_.X_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return sign_key_.remote_parties_[pos].X_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetN(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return sign_key_.local_party_.N_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return sign_key_.remote_parties_[pos].N_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetS(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return sign_key_.local_party_.s_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return sign_key_.remote_parties_[pos].s_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

const safeheron::bignum::BN& Context::GetT(const std::string& party_id)  const{
    if(sign_key_.local_party_.party_id_ == party_id) {
        return sign_key_.local_party_.t_;
    }
    int pos = sign_key_.get_remote_party_pos(party_id);
    if(pos != -1) return sign_key_.remote_parties_[pos].t_;
    throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, ("Invalid party_id: " + party_id).c_str());;
}

void Context::ExportDF(std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_D,
                       std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_F) const{
    for(size_t j = 0; j < sign_key_.remote_parties_.size(); ++j){
        all_D[sign_key_.local_party_.party_id_][sign_key_.remote_parties_[j].party_id_] = remote_parties_[j].D_ji;
        all_F[sign_key_.local_party_.party_id_][sign_key_.remote_parties_[j].party_id_] = remote_parties_[j].F_ji;
    }
}

void Context::ExportD_hat_F_hat(std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_D_hat,
                                std::map<std::string, std::map<std::string,safeheron::bignum::BN>> &all_F_hat) const{
    for(size_t j = 0; j < sign_key_.remote_parties_.size(); ++j){
        all_D_hat[sign_key_.local_party_.party_id_][sign_key_.remote_parties_[j].party_id_] = remote_parties_[j].D_hat_ji;
        all_F_hat[sign_key_.local_party_.party_id_][sign_key_.remote_parties_[j].party_id_] = remote_parties_[j].F_hat_ji;
    }
}

void Context::ComputeSSID(const std::string &sid){
    // Compute ssid = (sid, g, q, P, rid, X, Y, N, s, t)
    const curve::Curve *curv = curve::GetCurveParam(sign_key_.X_.GetCurveType());
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
    auto GetY = [&](const BN &index) {
        for(const auto &party: sign_key_.remote_parties_){
            if(party.index_ == index) return party.Y_;
        }
        return sign_key_.local_party_.Y_;
    };
    auto GetN = [&](const BN &index) {
        for(const auto &party: sign_key_.remote_parties_){
            if(party.index_ == index) return party.N_;
        }
        return sign_key_.local_party_.N_;
    };
    auto GetS = [&](const BN &index) {
        for(const auto &party: sign_key_.remote_parties_){
            if(party.index_ == index) return party.s_;
        }
        return sign_key_.local_party_.s_;
    };
    auto GetT = [&](const BN &index) {
        for(const auto &party: sign_key_.remote_parties_){
            if(party.index_ == index) return party.t_;
        }
        return sign_key_.local_party_.t_;
    };

    // Construct an ordered party index array
    std::vector<safeheron::bignum::BN> t_party_index_arr;
    t_party_index_arr.push_back(sign_key_.local_party_.index_);
    for(const auto &party: sign_key_.remote_parties_){
        t_party_index_arr.push_back(party.index_);
    }
    std::sort(t_party_index_arr.begin(), t_party_index_arr.end());
    // Append all parties [ (i, X_i, Y_i, N_i, s_i, t_i) ]
    for (const auto & pi : t_party_index_arr) {
        sid_maker.Append(pi);
        sid_maker.Append(GetX(pi));
        sid_maker.Append(GetY(pi));
        sid_maker.Append(GetN(pi));
        sid_maker.Append(GetS(pi));
        sid_maker.Append(GetT(pi));
    }
    sid_maker.Finalize(ssid_);
}

void Context::ComputeSSID_Index(){
    std::string t_ssid;
    SIDMaker ssid_maker;

    // Set local sid_index = (sid, index)
    ssid_maker.Append(ssid_);
    ssid_maker.Append(sign_key_.local_party_.index_);
    ssid_maker.Finalize(local_party_.ssid_index_);

    for(size_t j = 0; j < remote_parties_.size(); ++j){
        // Set remote ssid_pid = (sid, pid, rid)
        ssid_maker.Reset();
        ssid_maker.Append(ssid_);
        ssid_maker.Append(sign_key_.remote_parties_[j].index_);
        ssid_maker.Finalize(remote_parties_[j].ssid_index_);
    }
}


}
}
}
}
