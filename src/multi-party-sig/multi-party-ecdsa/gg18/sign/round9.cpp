#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/round9.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace sign{

void Round9::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round9::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round9::ReceiveVerify(const std::string &party_id) {
    return true;
}

bool Round9::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    // Recovery parameter
    uint32_t recovery_param = (ctx->R_.y().IsOdd() ? 1 : 0) |     // is_y_odd
                          ((ctx->R_.x() != ctx->r_) ? 2 : 0); // is_second_key

    BN s = ctx->local_party_.si_;
    for (size_t i = 0; i < bc_message_arr_.size(); ++i) {
        s = (s + bc_message_arr_[i].si_) % curv->n;
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

bool Round9::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    // For final round, do nothing.
    return true;
}

}
}
}
}
