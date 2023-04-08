
#include "round3.h"
#include "context.h"
#include "crypto-commitment/commitment.h"
#include "crypto-curve/curve.h"
#include "crypto-hash/sha256.h"
#include "crypto-encode/hex.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::zkp::pedersen_proof::PedersenStatement;
using safeheron::zkp::pedersen_proof::PedersenWitness;
using safeheron::zkp::pedersen_proof::PedersenProof;
using safeheron::hash::CSHA256;
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeWitness;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
using safeheron::zkp::pail::PailEncGroupEleRangeProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    // bool ok = message_arr_[pos].FromBase64(msg);
    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round3::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);

    ok = ctx->ssid_ == p2p_message_arr_[pos].ssid_;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in ctx->ssid_ == message_arr_[pos].ssid_");
        return false;
    }

    ok = sign_key.remote_parties_[pos].index_ == p2p_message_arr_[pos].index_;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in sign_key.remote_parties_[pos].index_ == message_arr_[pos].index_");
        return false;
    }

    PailEncGroupEleRangeSetUp setup(sign_key.local_party_.N_,
                                      sign_key.local_party_.s_,
                                      sign_key.local_party_.t_);

    PailEncGroupEleRangeStatement statement(
            ctx->remote_parties_[pos].K_,
            ctx->remote_parties_[pos].pail_pub_.n(),
            ctx->remote_parties_[pos].pail_pub_.n_sqr(),
            curv->n,
            p2p_message_arr_[pos].Delta_,
            ctx->Gamma_,
            256, 512);

    ok = p2p_message_arr_[pos].psi_double_prime_ij_.Verify(setup, statement);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_double_prime_ij_.Verify(setup, statement)");
        return false;
    }

    ctx->remote_parties_[pos].delta_ = p2p_message_arr_[pos].delta_;
    ctx->remote_parties_[pos].Delta_ = p2p_message_arr_[pos].Delta_;

    return true;
}

bool Round3::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    // delta = Sum_i( delta_i )
    BN delta = ctx->local_party_.delta_;
    for (const auto & remote_party : ctx->remote_parties_) {
        delta = (delta + remote_party.delta_) % curv->n;
    }
    ctx->delta_ = delta;

    // Delta = Prod_i( Delta_i )
    CurvePoint Delta = ctx->local_party_.Delta_;
    for (const auto & remote_party : ctx->remote_parties_) {
        Delta = Delta + remote_party.Delta_;
    }

    ok = (curv->g * delta == Delta);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (curv->g * delta == Delta)");
        return false;
    }

    // R = Gamma^(delta^-1 mod q)
    ctx->R_ = ctx->Gamma_ * delta.InvM(curv->n);

    ctx->r_ = ctx->R_.x();

    // sigma = k * m + r * chi  mod q
    ctx->local_party_.sigma_ = (ctx->local_party_.k_ * ctx->m_ + ctx->r_ * ctx->local_party_.chi_ ) % curv->n;

    return true;
}

bool Round3::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round3P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.sigma_ = ctx->local_party_.sigma_;
        string base64;
        ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    return true;
}

}
}
}
}
