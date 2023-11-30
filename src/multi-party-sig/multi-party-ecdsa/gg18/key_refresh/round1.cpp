#include <cstdio>
#include "crypto-suites/crypto-commitment/commitment.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/round1.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::gg18::SignKey;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {


void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize bc_message from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ctx->remote_parties_[pos].V_ = bc_message_arr_[pos].V_;

    return true;
}

bool Round1::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    // DLN Proof
    ctx->local_party_.dln_proof_1_.Prove(sign_key.local_party_.N_tilde_,
                                        sign_key.local_party_.h1_,
                                        sign_key.local_party_.h2_,
                                        sign_key.local_party_.p_,
                                        sign_key.local_party_.q_,
                                        sign_key.local_party_.alpha_);
    ctx->local_party_.dln_proof_2_.Prove(sign_key.local_party_.N_tilde_,
                                        sign_key.local_party_.h2_,
                                        sign_key.local_party_.h1_,
                                        sign_key.local_party_.p_,
                                        sign_key.local_party_.q_,
                                        sign_key.local_party_.beta_);
    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round1P2PMessage message;
        message.x_ij_ = ctx->remote_parties_[i].x_ij_;
        string base64;
        bool ok = message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round1BCMessage message;
    message.vs_ = ctx->local_party_.vs_;
    message.N_tilde_ = sign_key.local_party_.N_tilde_;
    message.h1_ = sign_key.local_party_.h1_;
    message.h2_ = sign_key.local_party_.h2_;
    message.dln_proof_1_ = ctx->local_party_.dln_proof_1_;
    message.dln_proof_2_ = ctx->local_party_.dln_proof_2_;
    message.pail_pub_ = sign_key.local_party_.pail_pub_;
    message.blind_factor_ = ctx->local_party_.blind_factor_;
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
