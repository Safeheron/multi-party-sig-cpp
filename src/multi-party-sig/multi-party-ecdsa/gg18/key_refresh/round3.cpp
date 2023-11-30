#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/round3.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/context.h"

using std::string;
using std::vector;
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
namespace key_refresh {

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round3::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }
    bool ok = p2p_message_arr_[pos].dlog_proof_x_.Verify();
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify commitment of schnorr proof of hd_sign key share!");
        return false;
    }

    ok = p2p_message_arr_[pos].pail_proof_.Verify(sign_key.remote_parties_[pos].pail_pub_.n());
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify paillier proof!");
        return false;
    }

    safeheron::zkp::no_small_factor_proof::NoSmallFactorSetUp set_up(sign_key.local_party_.N_tilde_,
                                                                     sign_key.local_party_.h1_,
                                                                     sign_key.local_party_.h2_);
    safeheron::zkp::no_small_factor_proof::NoSmallFactorStatement statement(sign_key.remote_parties_[pos].pail_pub_.n(), 256, 512);
    ok = p2p_message_arr_[pos].nsf_proof_.Verify(set_up, statement);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ok = message_arr_[pos].nsf_proof_.Verify(set_up, statement)");
        return false;
    }

    return true;
}

bool Round3::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    vector<BN> &l_arr = ctx->local_party_.l_arr_;
    const CurvePoint &local_X = curv->g * ctx->local_party_.new_x_;
    CurvePoint pub = local_X * l_arr.back();
    for (size_t i = 0; i < p2p_message_arr_.size(); ++i) {
        const CurvePoint &remote_X = p2p_message_arr_[i].dlog_proof_x_.pk_;
        pub += remote_X * l_arr[i];
    }

    ok = (pub == sign_key.X_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "pub == sign_key.pub_");
        return false;
    }

    for (size_t i = 0; i < p2p_message_arr_.size(); ++i) {
        sign_key.remote_parties_[i].g_x_ = p2p_message_arr_[i].dlog_proof_x_.pk_;
    }
    sign_key.local_party_.x_ = ctx->local_party_.new_x_;
    sign_key.local_party_.g_x_ = curv->g * sign_key.local_party_.x_;
    ok = sign_key.ValidityTest();
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in sign_key.ValidityTest()");
        return false;
    }
    ctx->local_party_.ack_status_ = 1; // ack
    return true;
}

bool Round3::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round3BCMessage message;
    message.ack_status_ = ctx->local_party_.ack_status_;
    bool ok = message.ToBase64(out_bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
        return false;
    }

    return true;
}


}
}
}
}
