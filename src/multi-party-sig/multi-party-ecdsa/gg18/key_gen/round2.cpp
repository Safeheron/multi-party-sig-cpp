
#include <cstdio>
#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round2.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::zkp::pail::PailProof;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_gen {

void Round2::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
        bc_message_arr_.emplace_back();
    }
}

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64(bc)!");
        return false;
    }

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64(p2p)!");
        return false;
    }

    return true;
}

bool Round2::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    BN commitment = safeheron::commitment::CreateComWithBlind(bc_message_arr_[pos].kgd_y_.point_,
                                                              bc_message_arr_[pos].kgd_y_.blind_factor_);
    ok = (commitment == ctx->remote_parties_[pos].kgc_y_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify commitment of y!");
        return false;
    }

    if (!safeheron::sss::vsss::VerifyShare(bc_message_arr_[pos].vs_, sign_key.threshold_, sign_key.local_party_.index_, p2p_message_arr_[pos].x_ij_, curv->g, curv->n)) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify VsssSecp256k1::VerifyShare!");
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

    ctx->remote_parties_[pos].y_ = bc_message_arr_[pos].kgd_y_.point_;

    return true;
}

bool Round2::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);

    CurvePoint pub = ctx->local_party_.y_;

    for (size_t i = 0; i < bc_message_arr_.size(); ++i) {
        pub += bc_message_arr_[i].kgd_y_.point_;
    }

    ok = !pub.IsInfinity();
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid public key!");
        return false;
    }

    ctx->X_ = pub;

    sign_key.X_ = pub;

    // Compute the new share
    for (size_t i = 0; i < bc_message_arr_.size(); ++i) {
        sign_key.local_party_.x_ = (sign_key.local_party_.x_ + p2p_message_arr_[i].x_ij_) % curv->n;
    }
    sign_key.local_party_.g_x_ = curv->g * sign_key.local_party_.x_;

    // Schnorr Non-interactive Zero-Knowledge Proof
    ctx->local_party_.rand_num_for_schnorr_proof_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.dlog_proof_x_.ProveWithREx(sign_key.local_party_.x_, ctx->local_party_.rand_num_for_schnorr_proof_, ctx->curve_type_);

    // Paillier proof
    ctx->local_party_.pail_proof_.Prove(sign_key.local_party_.pail_pub_.n(),
                                        sign_key.local_party_.pail_priv_.p(),
                                        sign_key.local_party_.pail_priv_.q());

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round2BCMessage message;
    message.pub_ = sign_key.X_;
    message.dlog_proof_x_ = ctx->local_party_.dlog_proof_x_;
    message.pail_proof_ = ctx->local_party_.pail_proof_;
    string base64;
    bool ok = message.ToBase64(out_bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64(Round2BCMessage)!");
        return false;
    }

    return true;
}

}
}
}
}
