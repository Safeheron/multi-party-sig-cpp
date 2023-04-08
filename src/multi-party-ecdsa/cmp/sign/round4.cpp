
#include "round4.h"
#include <vector>
#include "context.h"
#include "crypto-commitment/commitment.h"
#include "crypto-curve/curve.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
using safeheron::zkp::pail::PailEncGroupEleRangeWitness;
using safeheron::zkp::pail::PailEncGroupEleRangeProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

void Round4::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round4::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round4::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

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

    ctx->remote_parties_[pos].sigma_ = p2p_message_arr_[pos].sigma_;

    return true;
}

bool Round4::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = ctx->GetCurrentCurve();

    // Recovery parameter
    uint32_t recovery_param = (ctx->R_.y().IsOdd() ? 1 : 0) |     // is_y_odd
                              ((ctx->R_.x() != ctx->r_) ? 2 : 0); // is_second_key

    BN s = ctx->local_party_.sigma_;
    for (auto & remote_party : ctx->remote_parties_) {
        s = (s + remote_party.sigma_) % curv->n;
    }
    s = s % curv->n;

    // Low S
    BN half_n = curv->n / 2;
    if (s > half_n){
        s = curv->n - s;
        recovery_param ^= 1;
    }
    ctx->s_ = s;
    ctx->v_ = recovery_param;

    // Verify the signature
    ok = safeheron::curve::ecdsa::VerifyPublicKey(sign_key.X_, sign_key.X_.GetCurveType(), ctx->m_, ctx->r_, ctx->s_, ctx->v_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify R,S,V with child public key!");
        return false;
    }

    return true;
}

bool Round4::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    return true;
}

}
}
}
}
